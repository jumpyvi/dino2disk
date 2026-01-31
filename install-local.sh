#!/bin/sh
set -eu

# Install this project into $HOME/.local
PREFIX="$HOME/.local"

sudo rm -rf $PREFIX/share/org.projectbluefin.dakoinstaller

if [ ! -d build ]; then
  meson setup build --prefix="$PREFIX"
else
  meson setup build --reconfigure --prefix="$PREFIX"
fi

ninja -C build
sudo ninja -C build install

echo "Installed to $PREFIX"
