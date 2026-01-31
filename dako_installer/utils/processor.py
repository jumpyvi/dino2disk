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
    def set_log_callback(callback):
        """Set callback to be called for each log message."""
        _cb_handler.set_callback(callback)

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
        setup_steps.append([disk, "mount", [boot_partition, f"{mount_point}/boot", True]])

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

        # Sync and cleanup
        setup_steps.append([disk, "sync-unmount", [mount_point, encrypt]])

        # Mountpoints
        mountpoints.append([root_mapper, "/"])
        mountpoints.append([boot_partition, "/boot"])

        return setup_steps, mountpoints, boot_partition, root_partition

    @staticmethod
    def gen_install_recipe(log_path, finals, sys_recipe):
        """Execute bootc-based installation directly without writing recipe"""
        logger.info("processing the following final data: %s", finals)

        recipe = BootcRecipe()
        image = "ghcr.io/projectbluefin/dakota"

        # Setup encryption if user selected it
        encrypt = False
        password = None
        for final in finals:
            if "encryption" in final.keys():
                encrypt = final["encryption"]["use_encryption"]
                password = final["encryption"]["encryption_key"] if encrypt else None

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
                    args=(setup_steps, encrypt, password, boot_part, root_part),
                    daemon=True
                )
                thread.start()

        return recipe

    @staticmethod
    def __execute_disk_operations(setup_steps, encrypt, password, boot_partition, root_partition):
        """Execute disk operations using subprocess in background"""
        uuids = {}
        success = True
        
        # Initialize log file
        log_command_output("=" * 80)
        log_command_output("Dakota Installation Log Started")
        log_command_output("=" * 80)
        
        for step in setup_steps:
            disk, operation, params = step[0], step[1], step[2]
            
            try:
                if operation == "cleanup":
                    mount_point = params[0]
                    logger.info("Cleaning up previous state at %s", mount_point)
                    log_command_output(f"OPERATION: cleanup at {mount_point}")
                    
                    # Unmount specific partitions first
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
                    
                    logger.info("Boot UUID: %s, LUKS UUID: %s", uuids["BOOT_UUID"], uuids["LUKS_UUID"])
                    
                elif operation == "bootc-install":
                    mount_point, root_name = params
                    log_command_output(f"OPERATION: bootc-install")
                    image = "ghcr.io/projectbluefin/dakota"
                    
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
                        "--karg", f"rd.luks.name={uuids.get('LUKS_UUID', 'unknown')}=cryptroot",
                        "--karg", "root=/dev/mapper/cryptroot",
                        "--karg", "rootflags=subvol=/",
                        "--karg", "rw"
                    ]
                    logger.info("Running bootc install to-filesystem")
                    log_command_output(f"Command: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                elif operation == "remount-rw":
                    mount_point = params[0]
                    logger.info("Remounting %s as writable", mount_point)
                    log_command_output(f"OPERATION: remount-rw")
                    
                    cmd1 = ["sudo", "mount", "-o", "remount,rw", mount_point]
                    log_command_output(f"Command: {' '.join(cmd1)}")
                    result = subprocess.run(cmd1, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                    cmd2 = ["sudo", "mount", "-o", "remount,rw", f"{mount_point}/boot"]
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
                        
                        cmd = ["sudo", "bash", "-c", f"echo '{crypttab_content}' | sudo tee {deploy_dir}/etc/crypttab"]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
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
                        
                        fstab_content = "/dev/mapper/cryptroot  /      btrfs  defaults  0 0\nUUID={BOOT_UUID}      /boot  vfat   defaults  0 2".format(
                            BOOT_UUID=uuids.get("BOOT_UUID", "unknown")
                        )
                        logger.info("Creating fstab at %s/etc/fstab", deploy_dir)
                        log_command_output(f"Creating fstab at {deploy_dir}/etc/fstab")
                        log_command_output(f"Content: {fstab_content}")
                        
                        cmd = ["sudo", "bash", "-c", f"echo -e '{fstab_content}' | sudo tee {deploy_dir}/etc/fstab"]
                        log_command_output(f"Command: {' '.join(cmd)}")
                        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                    except Exception as e:
                        logger.warning("Failed to configure fstab: %s", e)
                        log_command_output(f"ERROR: Failed to configure fstab: {e}")
                    
                elif operation == "sync-unmount":
                    mount_point, encrypt = params
                    logger.info("Syncing and unmounting")
                    log_command_output(f"OPERATION: sync-unmount")
                    
                    cmd1 = ["sudo", "sync"]
                    log_command_output(f"Command: {' '.join(cmd1)}")
                    result = subprocess.run(cmd1, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                    cmd2 = ["sudo", "umount", "-R", mount_point]
                    log_command_output(f"Command: {' '.join(cmd2)}")
                    result = subprocess.run(cmd2, check=True, capture_output=True, text=True)
                    log_command_output(f"Return code: {result.returncode}")
                    if result.stdout:
                        log_command_output(f"Stdout: {result.stdout}")
                    if result.stderr:
                        log_command_output(f"Stderr: {result.stderr}")
                    
                    if encrypt:
                        cmd3 = ["sudo", "cryptsetup", "close", "cryptroot"]
                        log_command_output(f"Command: {' '.join(cmd3)}")
                        result = subprocess.run(cmd3, check=True, capture_output=True, text=True)
                        log_command_output(f"Return code: {result.returncode}")
                        if result.stdout:
                            log_command_output(f"Stdout: {result.stdout}")
                        if result.stderr:
                            log_command_output(f"Stderr: {result.stderr}")
                        
            except subprocess.CalledProcessError as e:
                error_msg = f"Command failed: {e.cmd}\nReturn code: {e.returncode}"
                if e.stdout:
                    error_msg += f"\nStdout: {e.stdout if isinstance(e.stdout, str) else e.stdout.decode()}"
                if e.stderr:
                    error_msg += f"\nStderr: {e.stderr if isinstance(e.stderr, str) else e.stderr.decode()}"
                logger.error(error_msg)
                log_command_output(f"ERROR: {error_msg}")
                success = False
                break
                
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
            logger.info("Scheduling completion callback on main thread with success=%s", success)
            GLib.idle_add(Processor.__completion_callback, success)