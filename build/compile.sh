#!/bin/bash

echo "Enhanced PE Crypter Build Script (Cross-Compilation)"
echo "===================================================="

export CC=x86_64-w64-mingw32-gcc
export CFLAGS="-Wall -O2 -std=c99"
export LDFLAGS="-lkernel32 -luser32 -ladvapi32"

if ! command -v $CC &> /dev/null; then
    echo "❌ Cross-compiler $CC not found"
    echo "Please install mingw-w64:"
    echo "  Ubuntu/Debian: sudo apt-get install gcc-mingw-w64"
    exit 1
fi

echo "✓ Cross-compiler found: $CC"
echo

echo "[1/2] Building enhanced crypter..."
$CC $CFLAGS -o enhanced_crypter.exe \
    ../enhanced_components/enhanced_loader/enhanced_loader.c \
    ../enhanced_components/enhanced_loader/payload_decryption.c \
    ../enhanced_components/eat_hooking/eat_hooker.c \
    ../enhanced_components/eat_hooking/api_hooks.c \
    ../enhanced_components/evasion/vm_detection.c \
    ../enhanced_components/evasion/sandbox_detection.c \
    ../enhanced_components/evasion/debugger_detection.c \
    $LDFLAGS

if [ $? -eq 0 ]; then
    echo "✓ Enhanced crypter built successfully"
else
    echo "❌ Failed to build enhanced crypter"
    exit 1
fi

echo "[2/2] Building validation suite..."
$CC $CFLAGS -o validation_suite.exe \
    ../testing/validation_suite.c \
    ../enhanced_components/eat_hooking/eat_hooker.c \
    ../enhanced_components/evasion/vm_detection.c \
    ../enhanced_components/evasion/sandbox_detection.c \
    ../enhanced_components/evasion/debugger_detection.c \
    $LDFLAGS

if [ $? -eq 0 ]; then
    echo "✓ Validation suite built successfully"
else
    echo "❌ Failed to build validation suite"
    exit 1
fi

echo
echo "=========================================="
echo "Build Complete!"
echo "=========================================="
if [ -f "enhanced_crypter.exe" ]; then echo "✓ enhanced_crypter.exe"; fi
if [ -f "validation_suite.exe" ]; then echo "✓ validation_suite.exe"; fi

echo
echo "Testing with Wine..."
if command -v wine &> /dev/null; then
    wine validation_suite.exe
else
    echo "⚠️ Wine not installed - skipping validation"
fi

chmod +x *.exe
echo "✓ Build script completed successfully!"
