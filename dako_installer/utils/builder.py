# builder.py
#
# Copyright 2024 mirkobrombin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundationat version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import os
import subprocess
import sys
from gettext import gettext as _

from dako_installer.defaults.conn_check import VanillaDefaultConnCheck
from dako_installer.defaults.disk import VanillaDefaultDisk
from dako_installer.defaults.encryption import VanillaDefaultEncryption
from dako_installer.defaults.image import VanillaDefaultImage
from dako_installer.defaults.keyboard import VanillaDefaultKeyboard
from dako_installer.defaults.language import VanillaDefaultLanguage
from dako_installer.defaults.network import VanillaDefaultNetwork
from dako_installer.defaults.timezone import VanillaDefaultTimezone
from dako_installer.defaults.welcome import VanillaDefaultWelcome
from dako_installer.layouts.preferences import VanillaLayoutPreferences
from dako_installer.layouts.yes_no import VanillaLayoutYesNo
logger = logging.getLogger("Installer::Builder")

# Hardcoded recipe to replace RecipeLoader
hardcoded_recipe = {
    "tour": {
        "welcome": {
            "resource": "/org/projectbluefin/dakoinstaller/assets/welcome.png",
            "title": "Installing Dakota",
            "description": "The process could take a few minutes, please be patient"
        },
        "control": {
            "resource": "/org/projectbluefin/dakoinstaller/assets/ready.svg",
            "title": "Always Ready",
            "description": "Don't be held back by your system, use it the way you want"
        },
        "containerized": {
            "resource": "/org/projectbluefin/dakoinstaller/assets/containerized.svg",
            "title": "Containerized",
            "description": "You never have to worry about breakage due to incompatible or conflicting packages"
        },
        "completed": {
            "resource": "/org/projectbluefin/dakoinstaller/assets/complete.svg",
            "title": "Complete and Reliable",
            "description": "The largest software catalog at your fingertips"
        }
    },
    "steps": {
        "welcome": {
            "template": "welcome",
            "protected": True
        },
        "network": {
            "template": "network",
        },
        "image": {
            "template": "image",
            "custom_image": True
        },
        "disk": {
            "template": "disk"
        },
        "encryption": {
            "template": "encryption"
        }
    }
}


templates = {
    "network": VanillaDefaultNetwork,
    "conn-check": VanillaDefaultConnCheck,
    "welcome": VanillaDefaultWelcome,
    "language": VanillaDefaultLanguage,
    "keyboard": VanillaDefaultKeyboard,
    "timezone": VanillaDefaultTimezone,
    "preferences": VanillaLayoutPreferences,
    "disk": VanillaDefaultDisk,
    "encryption": VanillaDefaultEncryption,
    "image": VanillaDefaultImage,
    "yes-no": VanillaLayoutYesNo,
}


class Builder:
    def __init__(self, window):
        self.__window = window
        self.__recipe = hardcoded_recipe
        self.__register_widgets = []
        self.__register_finals = []
        self.__property_list = []
        self.__load()

    def __load(self):
        self.__window.recipe = self.recipe

        log_path = "/tmp/dako.log"

        if not os.path.exists(log_path):
            try:
                open(log_path, "a").close()
            except OSError:
                logger.warning(_("failed to create log file: %s") % log_path)
                logging.warning(_("No log will be stored."))
        
        for key, step in self.recipe["steps"].items():
            if step["template"] not in templates:
                logger.error(_("Unknown template: %s") % step["template"])
                sys.exit(1)

            self.__register_widgets.append(
                (templates[step["template"]](
                    self.__window, self.distro_info, key, step
                ), step)
            )

    def get_finals(self):
        self.__register_finals = []

        for widget, _ in self.__register_widgets:
            self.__register_finals.append(widget.get_finals())

        return self.__register_finals

    @property
    def widgets(self):
        return self.__register_widgets

    @property
    def recipe(self):
        return self.__recipe

    @property
    def property_list(self):
        return self.__property_list

    @property
    def distro_info(self):
        return {
            "name": "Dakoraptor",
            "logo": "dako",
        }
