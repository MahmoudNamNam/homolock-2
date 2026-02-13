#!/usr/bin/env bash
# Build and install SEAL-Python (Huelse) for HomoLock-HR. Python-only app; this installs the seal Python package.
# Try "pip install seal" first; use this script only if you need to build from source.
# Run from server_py/ with: bash install_seal_python.sh
# Requires: git, cmake, pip, and a compiler (Xcode CLI or brew install gcc on macOS).

set -e
cd "$(dirname "$0")"
SEAL_PY="${1:-SEAL-Python}"

if [ ! -d "$SEAL_PY" ]; then
  echo "Cloning SEAL-Python..."
  git clone https://github.com/Huelse/SEAL-Python.git "$SEAL_PY"
fi
cd "$SEAL_PY"

echo "Initializing submodules (SEAL native + pybind11)..."
git submodule update --init --recursive

echo "Building Microsoft SEAL native library..."
cd SEAL
cmake -S . -B build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
cmake --build build
# setup.py expects SEAL/build/lib/*.a; SEAL 4 may put the .a elsewhere
mkdir -p build/lib
if [ -z "$(ls -A build/lib/*.a 2>/dev/null)" ]; then
  SEAL_A=$(find build -name "*.a" -type f 2>/dev/null | head -1)
  if [ -n "$SEAL_A" ]; then
    cp "$SEAL_A" build/lib/
    echo "Copied $SEAL_A to build/lib/"
  fi
fi
cd ..

echo "Installing Python package (numpy, pybind11, then seal)..."
pip install numpy pybind11
pip install .
echo "Done. Test with: python3 -c 'import seal; print(seal)'"
cd ..
