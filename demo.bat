@echo off
:: Check if CMake is installed
where cmake >nul 2>&1
if %errorlevel% equ 0 (
    echo CMake found. Running CMake build...
    cmake -S . -B build && cmake --build build --parallel
    if %errorlevel% neq 0 (
        echo CMake build failed. Exiting with error code %errorlevel%.
        pause
        exit /b %errorlevel%
    )
) else (
    echo CMake not found. Running build.bat...
    call build.bat
    if %errorlevel% neq 0 (
        echo build.bat failed. Exiting with error code %errorlevel%.
        pause
        exit /b %errorlevel%
    )
)

echo Build completed successfully.

:: Clear previous public keys file if it exists
if exist employee_public_keys.txt (
    del employee_public_keys.txt
)

echo Generating client seeds and collecting public keys...
for /L %%i in (1,1,%1) do (
    echo Running build\seedgen.exe private_seed\client%%i.seed
    build\seedgen.exe private_seed\client%%i.seed >> employee_public_keys.txt
    if %errorlevel% neq 0 (
        echo seedgen.exe failed for client%%i.seed. Exiting with error code %errorlevel%.
        pause
        exit /b %errorlevel%
    )
)
echo Public keys appended to employee_public_keys.txt

echo Spawning client processes...
for /L %%i in (1,1,%1) do (
    start "Client %%i" cmd.exe /k "mode con:cols=120 lines=40 && build\client.exe private_seed\client%%i.seed"
)

echo Spawning server process...
start "Server" cmd.exe /k "build\server.exe employee_public_keys.txt"

echo All processes spawned.
endlocal
exit /b 0
