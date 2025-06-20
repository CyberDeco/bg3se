#!/bin/bash
set -euo pipefail

# Auto-install Homebrew dependencies
if ! command -v brew &>/dev/null; then
  echo "Homebrew not found. Please install Homebrew first: https://brew.sh"
  exit 1
fi

echo "🏡 Installing Homebrew dependencies..."
brew bundle --file=Brewfile

# Create build directory and configure
echo "📦 Bootstrapping project via CMake"
cmake -G Ninja --preset bg3se_macos_debug

# Build the project
echo "🚧 Building"
cmake -G Ninja --build --preset bg3se_macos_debug --target clean
