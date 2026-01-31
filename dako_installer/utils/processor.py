# processor.py
#
# Simplified installer processor for Dakota
# Generates bootc-based installation recipes

import json
import logging
import os
import re
import subprocess
import tempfile
import threading
from datetime import datetime
from typing import Any, Union

from gi.repository import GLib
from dako_installer.core.disks import Diskutils, Disk
from dako_installer.core.system import Systeminfo

logger = logging.getLogger("Installer::Processor")

# Log file for all command output
COMMAND_LOG_FILE = "/tmp/dako.log"

def log_command_output(message):
    """Append message to command log file"""
    try:
        with open(COMMAND_LOG_FILE, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        logger.warning("Failed to write to command log: %s", e)

class CallbackHandler(logging.Handler):
    """Logging handler that sends logs to a callback function"""
    def __init__(self):
        super().__init__()
        self.__callback = None
    
    def set_callback(self, callback):
        self.__callback = callback
        
    def emit(self, record):
        if self.__callback:
            msg = self.format(record)
            GLib.idle_add(self.__callback, msg)


class BootcRecipe:
    """Simple recipe for bootc-based installation"""
    def __init__(self) -> None:
        self.disk: str = ""
        self.boot_partition: str = ""
        self.root_partition: str = ""
        self.encrypt: bool = False
        self.password: str | None = None
        self.image: str = ""
        self.mount_point: str = "/var/mnt"

    def to_dict(self) -> dict:
        return {
            "disk": self.disk,
            "boot_partition": self.boot_partition,
            "root_partition": self.root_partition,
            "encrypt": self.encrypt,
            "image": self.image,
            "mount_point": self.mount_point,
        }


class Processor:
    # Class variable to hold completion callback
    __completion_callback = None

    @staticmethod
    def set_completion_callback(callback):
        """Set callback to be called when disk operations complete. 
        Callback should accept a boolean 'success' argument."""
        Processor.__completion_callback = callback

    @staticmethod
    def __gen_simple_partition_steps(
        disk: str,
        encrypt: bool,
        password: str | None = None,
    ):
        """Generate simple partition steps: 2G boot + rest as root"""
        setup_steps = []
        mountpoints = []

        # Determine partition prefix
        part_prefix = "p" if re.match(r"[0-9]", disk[-1]) else ""

        boot_partition = f"{disk}{part_prefix}1"
        root_partition = f"{disk}{part_prefix}2"

        # Cleanup from previous attempts
        mount_point = "/var/mnt"
        setup_steps.append([disk, "cleanup", [mount_point]])

        # Partitioning
        setup_steps.append([disk, "wipefs", ["-a", disk]])
        setup_steps.append([disk, "sgdisk", ["-o", disk]])
        setup_steps.append([disk, "sgdisk", ["-n", "1:0:+2G", "-t", "1:ef00", "-c", "1:BOOT", disk]])
        setup_steps.append([disk, "sgdisk", ["-n", "2:0:0", "-t", "2:8300", "-c", "2:ROOT", disk]])

        # LUKS formatting on root
        if encrypt:
            assert password
            setup_steps.append([disk, "cryptsetup-format", [root_partition]])
            setup_steps.append([disk, "cryptsetup-open", [root_partition, "cryptroot"]])
            root_mapper = "/dev/mapper/cryptroot"
        else:
            root_mapper = root_partition

        # Filesystem creation
        setup_steps.append([disk, "mkfs.fat", ["-F", "32", "-n", "BOOT", boot_partition]])
        setup_steps.append([disk, "mkfs.btrfs", ["-L", "ROOT", "-f", root_mapper]])

        # Mount filesystems
        mount_point = "/var/mnt"
        setup_steps.append([disk, "mount", [root_mapper, mount_point, False]])
        setup_steps.append([disk, "mount", [boot_partition, f"{mount_point}/boot/efi", True]])

        # Get UUIDs
        setup_steps.append([disk, "get-uuids", [boot_partition, root_partition]])

        # Run bootc install
        setup_steps.append([disk, "bootc-install", [mount_point, root_partition if not encrypt else "cryptroot"]])

        # Remount as writable
        setup_steps.append([disk, "remount-rw", [mount_point]])

        # Configure crypttab and fstab
        if encrypt:
            setup_steps.append([disk, "configure-crypttab", [mount_point, root_partition]])
        
        setup_steps.append([disk, "configure-fstab", [mount_point, boot_partition, encrypt]])

        # Configure boot entries
        setup_steps.append([disk, "configure-boot-entries", [mount_point, boot_partition, encrypt]])

        # Sync and cleanup
        setup_steps.append([disk, "sync-unmount", [mount_point, encrypt]])

        # Mountpoints
        mountpoints.append([root_mapper, "/"])
        mountpoints.append([boot_partition, "/boot/efi"])

        return setup_steps, mountpoints, boot_partition, root_partition
    
    
    @staticmethod
    def _keep_sudo_alive(stop_event):
        """Periodically runs sudo -v to keep the timestamp from expiring"""
        while not stop_event.is_set():
            subprocess.run(["sudo", "-v"], check=False)
            stop_event.wait(60)

    @staticmethod
    def gen_install_recipe(log_path, finals, sys_recipe):
        """Execute bootc-based installation directly without writing recipe"""
        logger.info("processing the following final data: %s", finals)

        recipe = BootcRecipe()

        # Setup encryption if user selected it
        encrypt = False
        password = None
        for final in finals:
            if "encryption" in final.keys():
                encrypt = final["encryption"]["use_encryption"]
                password = final["encryption"]["encryption_key"] if encrypt else None
            if "custom_image" in final.keys(): # Extract custom_image from finals
                recipe.image = final["custom_image"]
                logger.info("Using custom image: %s", recipe.image)
            elif "default-image" in final.keys():
                recipe.image = "ghcr.io/projectbluefin/dakota:latest"
                logger.info("Using default image: %s", recipe.image)


        # Get disk selection and partition configuration
        for final in finals:
            if "disk" in final.keys():
                if "auto" in final["disk"].keys():
                    disk = final["disk"]["auto"]["disk"]
                else:
                    # For manual partitioning, use the first disk from the recipe
                    disk = list(final["disk"].keys())[0]
                    disk = Diskutils.separate_device_and_partn(disk)[0]

                # Generate partition steps
                setup_steps, mountpoints, boot_part, root_part = Processor.__gen_simple_partition_steps(
                    disk, encrypt, password
                )
                
                recipe.disk = disk
                recipe.boot_partition = boot_part
                recipe.root_partition = root_part
                recipe.encrypt = encrypt
                recipe.password = password

                # Execute the disk operations in background thread
                logger.info("Starting disk partitioning and formatting on %s", disk)
                thread = threading.Thread(
                    target=Processor.__execute_disk_operations,
                    args=(setup_steps, encrypt, password, boot_part, root_part, recipe.image),
                    daemon=True
                )
                thread.start()

        return recipe

    @staticmethod
    def __execute_disk_operations(setup_steps, encrypt, password, boot_partition, root_partition, image):
        """Execute disk operations using subprocess in background"""
        uuids = {}
        success = True

        stop_sudo_keepalive = threading.Event()
        keepalive_thread = threading.Thread(
            target=Processor._keep_sudo_alive, 
            args=(stop_sudo_keepalive,), 
            daemon=True
        )
        keepalive_thread.start()
        
        # Initialize log file
        log_command_output("=" * 80)
        log_command_output("Dakota Installation Log Started")
        log_command_output("=" * 80)
        
        for step in setup_steps:
            disk, operation, params = step[0], step[1], step[2]
            
            try:
                if operation == "remount-rw":
                    mount_point = params[0]
                    logger.info("Remounting %s as writable", mount_point)
                    log_command_output(f"OPERATION: remount-rw")
                    cmd = ["sudo", "mount", "-o", "remount,rw", mount_point]
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                
                elif operation == "cleanup":
                    mount_point = params[0]
                    logger.info("Cleaning up previous state at %s", mount_point)
                    log_command_output(f"OPERATION: cleanup at {mount_point}")
                    
                    for part in [boot_partition, root_partition]:
                        result = subprocess.run(["sudo", "umount", part], 
                                     check=False, capture_output=True, text=True)
                        log_command_output(f"Command: sudo umount {part}")
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")

                    # Unmount any previous mounts recursively
                    result = subprocess.run(["sudo", "umount", "-R", mount_point], 
                                 check=False, capture_output=True, text=True)
                    log_command_output(f"Command: sudo umount -R {mount_point}")
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                    # Close any LUKS devices
                    result = subprocess.run(["sudo", "cryptsetup", "close", "cryptroot"], 
                                 check=False, capture_output=True, text=True)
                    log_command_output(f"Command: sudo cryptsetup close cryptroot")
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                    # Remove mount point if it exists
                    result = subprocess.run(["sudo", "rmdir", mount_point], 
                                 check=False, capture_output=True, text=True)
                    log_command_output(f"Command: sudo rmdir {mount_point}")
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "wipefs":
                    cmd = ["sudo", "wipefs"] + params
                    logger.info("Executing: %s", " ".join(cmd))
                    log_command_output(f"OPERATION: wipefs")
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "sgdisk":
                    cmd = ["sudo", "sgdisk"] + params
                    logger.info("Executing: %s", " ".join(cmd))
                    log_command_output(f"OPERATION: sgdisk")
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "mkfs.fat":
                    cmd = ["sudo", "mkfs.fat"] + params
                    logger.info("Executing: %s", " ".join(cmd))
                    log_command_output(f"OPERATION: mkfs.fat")
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "mkfs.btrfs":
                    cmd = ["sudo", "mkfs.btrfs"] + params
                    logger.info("Executing: %s", " ".join(cmd))
                    log_command_output(f"OPERATION: mkfs.btrfs")
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "cryptsetup-format":
                    cmd = ["sudo", "cryptsetup", "luksFormat", "--type", "luks2", "--force-password"] + params
                    logger.info("Executing cryptsetup luksFormat")
                    log_command_output(f"OPERATION: cryptsetup-format")
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    password_input = f"{password}\n{password}\n" if password else ""
                    result = subprocess.run(cmd, input=password_input, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "cryptsetup-open":
                    cmd = ["sudo", "cryptsetup", "open"] + params
                    logger.info("Executing cryptsetup open")
                    log_command_output(f"OPERATION: cryptsetup-open")
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    password_input = f"{password}\n" if password else ""
                    result = subprocess.run(cmd, input=password_input, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "mount":
                    partition, mount_point, create_dir = params
                    logger.info("Mounting %s to %s", partition, mount_point)
                    log_command_output(f"OPERATION: mount")
                    
                    cmd = ["sudo", "mount", "--mkdir", partition, mount_point]
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "get-uuids":
                    boot_partition, root_partition = params
                    logger.info("Getting UUIDs for boot and root partitions")
                    log_command_output(f"OPERATION: get-uuids")
                    
                    # Get boot UUID
                    cmd = ["sudo", "blkid", "-s", "UUID", "-o", "value", boot_partition]
                    log_command_output(f"Command: {' '.join(cmd)}")
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    uuids["BOOT_UUID"] = result.stdout.strip()
                    log_command_output(f"Return code: {result.returncode}")
                    log_command_output(f"Boot UUID: {uuids['BOOT_UUID']}")
                    
                    # Get LUKS UUID
                    cmd = ["sudo", "blkid", "-s", "UUID", "-o", "value", root_partition]
                    log_command_output(f"Command: {' '.join(cmd)}")
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    uuids["LUKS_UUID"] = result.stdout.strip()
                    log_command_output(f"Return code: {result.returncode}")
                    log_command_output(f"LUKS UUID: {uuids['LUKS_UUID']}")
                    
                    
                elif operation == "bootc-install":
                    mount_point, root_name = params
                    log_command_output(f"OPERATION: bootc-install")
                    
                    cmd = [
                        "sudo", "podman", "run",
                        "--rm", "--privileged", "--pid=host",
                        "-v", "/etc/containers:/etc/containers:Z",
                        "-v", "/var/lib/containers:/var/lib/containers:Z",
                        "-v", "/dev:/dev",
                        "-e", "RUST_LOG=debug",
                        "-v", f"{mount_point}:{mount_point}",
                        "--security-opt", "label=type:unconfined_t",
                        f"{image}", "bootc", "install", "to-filesystem", f"{mount_point}",
                        "--composefs-backend",
                        "--bootloader", "systemd",
                        "--karg", "splash",
                        "--karg", "quiet",
                        "--karg", "rootflags=subvol=/",
                        "--karg", "rw"
                    ]
                    
                    # Add root kernel parameters if needed
                    if encrypt:
                        cmd.extend([
                            "--karg", f"rd.luks.name={uuids.get('LUKS_UUID', 'unknown')}=cryptroot",
                            "--karg", "root=/dev/mapper/cryptroot"
                        ])
                    else:
                        cmd.extend([
                            "--karg", f"root={root_partition}"
                        ])
                    
                    logger.info("Running bootc install to-filesystem")
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                    cmd2 = ["sudo", "mount", "-o", "remount,rw", f"{mount_point}/boot/efi"]
                    log_command_output(f"Command: {' '.join(cmd2)}")
                    result = subprocess.run(cmd2, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "configure-crypttab":
                    mount_point, root_partition = params
                    log_command_output(f"OPERATION: configure-crypttab")
                    
                    try:
                        cmd = ["sudo", "find", f"{mount_point}/state/deploy", "-maxdepth", "1", "-type", "d"]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                        
                        deploy_dirs = [d for d in result.stdout.strip().split('\n') if d and d != f"{mount_point}/state/deploy"]
                        if not deploy_dirs:
                            logger.warning("No deploy directory found, skipping crypttab")
                            log_command_output("WARNING: No deploy directory found, skipping crypttab")
                            continue
                        deploy_dir = deploy_dirs[0]
                        
                        crypttab_content = f"cryptroot UUID={uuids.get('LUKS_UUID', 'unknown')} none luks"
                        logger.info("Creating crypttab at %s/etc/crypttab", deploy_dir)
                        log_command_output(f"Creating crypttab at {deploy_dir}/etc/crypttab")
                        log_command_output(f"Content: {crypttab_content}")
                        
                        cmd = ["sudo", "tee", f"{deploy_dir}/etc/crypttab"]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, input=crypttab_content, check=True, capture_output=True, text=True)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                    except Exception as e:
                        logger.warning("Failed to configure crypttab: %s", e)
                        log_command_output(f"ERROR: Failed to configure crypttab: {e}")
                    
                elif operation == "configure-fstab":
                    mount_point, boot_partition, encrypt = params
                    log_command_output(f"OPERATION: configure-fstab")
                    
                    try:
                        cmd = ["sudo", "find", f"{mount_point}/state/deploy", "-maxdepth", "1", "-type", "d"]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                        
                        deploy_dirs = [d for d in result.stdout.strip().split('\n') if d and d != f"{mount_point}/state/deploy"]
                        if not deploy_dirs:
                            logger.warning("No deploy directory found, skipping fstab")
                            log_command_output("WARNING: No deploy directory found, skipping fstab")
                            continue
                        deploy_dir = deploy_dirs[0]
                        
                        if encrypt:
                            fstab_content = "/dev/mapper/cryptroot  /      btrfs  defaults  0 0\nUUID={BOOT_UUID}      /boot  vfat   defaults  0 2".format(
                                BOOT_UUID=uuids.get("BOOT_UUID", "unknown")
                            )
                        else:
                            fstab_content = "{ROOT_UUID}  /      btrfs  defaults  0 0\nUUID={BOOT_UUID}      /boot  vfat   defaults  0 2".format(
                                ROOT_UUID=root_partition,
                                BOOT_UUID=uuids.get("BOOT_UUID", "unknown")
                            )
                        logger.info("Creating fstab at %s/etc/fstab", deploy_dir)
                        log_command_output(f"Creating fstab at {deploy_dir}/etc/fstab")
                        log_command_output(f"Content: {fstab_content}")
                        
                        cmd = ["sudo", "tee", f"{deploy_dir}/etc/fstab"]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, input=fstab_content, check=True, capture_output=True, text=True)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                    except Exception as e:
                        logger.warning("Failed to configure fstab: %s", e)
                        log_command_output(f"ERROR: Failed to configure fstab: {e}")

                elif operation == "configure-boot-entries":
                    mount_point, boot_partition, encrypt = params
                    log_command_output(f"OPERATION: configure-boot-entries")

                    try:
                        # Find the deploy directory
                        cmd = ["sudo", "find", f"{mount_point}/state/deploy", "-maxdepth", "1", "-type", "d"]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                        
                        deploy_dirs = [d for d in result.stdout.strip().split('\n') if d and d != f"{mount_point}/state/deploy"]
                        if not deploy_dirs:
                            logger.warning("No deploy directory found, skipping boot entries")
                            log_command_output("WARNING: No deploy directory found, skipping boot entries")
                            continue
                        deploy_dir = deploy_dirs[0]
                        
                        # Get composefs hash from deploy directory basename
                        composefs_hash = os.path.basename(deploy_dir)
                        logger.info("Using composefs hash: %s", composefs_hash)
                        log_command_output(f"Using composefs hash: {composefs_hash}")
                        
                        # Get root filesystem UUID for non-encrypted installations
                        root_uuid = None
                        if not encrypt:
                            # Get the actual root filesystem UUID (not LUKS UUID)
                            cmd = ["sudo", "blkid", "-s", "UUID", "-o", "value", root_partition]
                            log_command_output(f"Command: {' '.join(cmd)}")
                            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                            root_uuid = result.stdout.strip()
                            logger.info("Root filesystem UUID: %s", root_uuid)
                            log_command_output(f"Root filesystem UUID: {root_uuid}")
                        
                        # Find the single boot entry file (there will always be only one)
                        boot_entries_dir = f"{mount_point}/boot/efi/loader/entries"
                        boot_entry = f"{boot_entries_dir}/bootc_bluefin_dakota-latest-1.conf"
                        
                        if not os.path.exists(boot_entry):
                            logger.warning("Boot entry file not found at expected location: %s", boot_entry)
                            log_command_output(f"WARNING: Boot entry file not found at expected location: {boot_entry}")
                            continue
                        
                        logger.info("Modifying boot entry: %s", boot_entry)
                        log_command_output(f"Modifying boot entry: {boot_entry}")
                        
                        # Read the current boot entry
                        cmd = ["sudo", "cat", boot_entry]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Current content:\n{result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                        
                        # Modify the options line
                        lines = result.stdout.strip().split('\n')
                        modified_lines = []
                        for line in lines:
                            if line.startswith('options '):
                                # Build the new options line
                                if encrypt:
                                    new_options = (
                                        f"options rd.luks.name={uuids.get('LUKS_UUID', 'unknown')}=cryptroot "
                                        f"rd.luks.uuid=luks-{uuids.get('LUKS_UUID', 'unknown')} "
                                        f"root=/dev/mapper/cryptroot "
                                        f"rootflags=subvol=/ rw "
                                        f"boot=UUID={uuids.get('BOOT_UUID', 'unknown')} "
                                        f"composefs={composefs_hash} splash quiet"
                                    )
                                else:
                                    # Use root UUID instead of device path for non-encrypted installations
                                    new_options = (
                                        f"options root=UUID={root_uuid} "
                                        f"rootflags=subvol=/ rw "
                                        f"boot=UUID={uuids.get('BOOT_UUID', 'unknown')} "
                                        f"composefs={composefs_hash} splash quiet"
                                    )
                                modified_lines.append(new_options)
                                log_command_output(f"Modified options line: {new_options}")
                            else:
                                modified_lines.append(line)
                        
                        # Write the modified content back
                        modified_content = '\n'.join(modified_lines) + '\n'
                        cmd = ["sudo", "tee", boot_entry]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, input=modified_content, check=True, capture_output=True, text=True)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                            
                    except Exception as e:
                        logger.warning("Failed to configure boot entries: %s", e)
                        log_command_output(f"ERROR: Failed to configure boot entries: {e}")
            except Exception as e:
                logger.error("Error during disk operation %s: %s", operation, e)
                log_command_output(f"ERROR during operation {operation}: {e}")
                success = False
                break
        
        if success:
            logger.info("Disk operations completed successfully")
            log_command_output("=" * 80)
            log_command_output("Installation completed successfully")
            log_command_output("=" * 80)
        else:
            logger.error("Disk operations failed")
            log_command_output("=" * 80)
            log_command_output("Installation FAILED")
            log_command_output("=" * 80)
        
        # Call completion callback if set - schedule on main thread
        if Processor.__completion_callback:
            stop_sudo_keepalive.set()
            keepalive_thread.join(timeout=1)
            logger.info("Scheduling completion callback on main thread with success=%s", success)
            GLib.idle_add(Processor.__completion_callback, success)