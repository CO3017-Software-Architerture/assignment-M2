@echo off
setlocal
pushd "%~dp0"

set "CXX=%CXX%"
if "%CXX%"=="" set "CXX=g++"
set "BUILD_DIR=build-bat"
set "OUTPUT=%BUILD_DIR%\assignment.exe"
set "SODIUM_INCLUDE="
set "SODIUM_LIB="

if defined SODIUM_ROOT (
    set "SODIUM_INCLUDE=-I%SODIUM_ROOT%\include"
    set "SODIUM_LIB=-L%SODIUM_ROOT%\lib"
)
if defined LIBSODIUM_ROOT if not defined SODIUM_ROOT (
    set "SODIUM_INCLUDE=-I%LIBSODIUM_ROOT%\include"
    set "SODIUM_LIB=-L%LIBSODIUM_ROOT%\lib"
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if errorlevel 1 goto :failed

if not exist "%SODIUM_INCLUDE:~2%\sodium.h" if not defined SODIUM_ROOT if not defined LIBSODIUM_ROOT (
    echo Using the compiler's default libsodium include and library paths.
)

for %%S in (main server qrgen data2qrlib) do (
    echo Compiling src\%%S.cpp...
    "%CXX%" -std=c++17 -Wall -Wextra -pedantic -Iheader %SODIUM_INCLUDE% -c "src\%%S.cpp" -o "%BUILD_DIR%\%%S.o"
    if errorlevel 1 goto :failed
)

echo Linking %OUTPUT%...
"%CXX%" "%BUILD_DIR%\main.o" "%BUILD_DIR%\server.o" "%BUILD_DIR%\qrgen.o" "%BUILD_DIR%\data2qrlib.o" %SODIUM_LIB% -lsodium -o "%OUTPUT%"
if errorlevel 1 goto :failed

echo Build succeeded: %OUTPUT%
if /I "%~1"=="run" "%OUTPUT%"
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:failed
echo Build failed.
popd
exit /b 1
