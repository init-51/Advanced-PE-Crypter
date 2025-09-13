@echo off
echo Enhanced PE Crypter Build Script
echo ================================

set COMPILER=gcc

where %COMPILER% >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: GCC compiler not found in PATH
    echo Please install MinGW-w64 or Visual Studio Build Tools
    pause
    exit /b 1
)

echo Compiler found: %COMPILER%
echo.

echo [1/2] Building enhanced crypter...
%COMPILER% -Wall -O2 -std=c99 -D_WIN32_WINNT=0x0601 -o enhanced_crypter.exe ^
    ../enhanced_components/integration/crypter_integration.c ^
    ../enhanced_components/enhanced_loader/enhanced_loader.c ^
    ../enhanced_components/enhanced_loader/payload_decryption.c ^
    ../enhanced_components/eat_hooking/eat_hooker.c ^
    ../enhanced_components/eat_hooking/api_hooks.c ^
    ../enhanced_components/evasion/vm_detection.c ^
    ../enhanced_components/evasion/sandbox_detection.c ^
    ../enhanced_components/evasion/debugger_detection.c ^
    -lkernel32 -luser32 -ladvapi32 -lpsapi

if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to build enhanced crypter
    pause
    exit /b 1
)
echo ✅ Enhanced crypter built successfully

echo [2/2] Building validation suite...
%COMPILER% -Wall -O2 -std=c99 -D_WIN32_WINNT=0x0601 -o validation_suite.exe ^
    ../testing/validation_suite.c ^
    ../enhanced_components/eat_hooking/eat_hooker.c ^
    ../enhanced_components/evasion/vm_detection.c ^
    ../enhanced_components/evasion/sandbox_detection.c ^
    ../enhanced_components/evasion/debugger_detection.c ^
    -lkernel32 -luser32 -ladvapi32 -lpsapi

if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to build validation suite
    pause
    exit /b 1
)
echo ✅ Validation suite built successfully

echo.
echo ==========================================
echo Build Complete!
echo ==========================================
echo Built files:
if exist enhanced_crypter.exe echo   ✅ enhanced_crypter.exe
if exist validation_suite.exe echo   ✅ validation_suite.exe

echo.
echo Testing installation...
echo Running validation suite...
validation_suite.exe

echo.
echo ==========================================
echo Build script completed successfully!
echo ==========================================

pause
