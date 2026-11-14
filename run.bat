@echo off
setlocal
pushd "%~dp0"
g++ -std=c++17 -Wall -Wextra -pedantic -Iheader ^
    src\main.cpp src\server.cpp src\Verifier.cpp src\qrgen.cpp ^
    src\NonceCache.cpp src\PassbackCache.cpp -lsodium -o main.exe
if errorlevel 1 (
    popd
    exit /b 1
)

main.exe %*
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%
