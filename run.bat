@echo off
setlocal
pushd "%~dp0"
set "CXX=g++"
set "OUTPUT=main.exe"
set "OBJDIR=input"

if not exist "%OBJDIR%" mkdir "%OBJDIR%"

call :compile_if_needed main
if errorlevel 1 goto :build_failed
call :compile_if_needed qrgen
if errorlevel 1 goto :build_failed
call :compile_if_needed employees
if errorlevel 1 goto :build_failed
call :compile_if_needed data2qrlib
if errorlevel 1 goto :build_failed

%CXX% -std=c++17 -Wall -Wextra -pedantic ^
    "%OBJDIR%\main.o" "%OBJDIR%\qrgen.o" "%OBJDIR%\employees.o" "%OBJDIR%\data2qrlib.o" ^
    -o "%OUTPUT%"
if errorlevel 1 (
    goto :build_failed
)

"%OUTPUT%"
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:compile_if_needed
set "SOURCE=src\%~1.cpp"
set "OBJECT=%OBJDIR%\%~1.o"
powershell -NoProfile -Command "$source = Get-Item '%SOURCE%'; $headers = Get-ChildItem 'header\*.hpp'; if (!(Test-Path '%OBJECT%') -or $source.LastWriteTime -gt (Get-Item '%OBJECT%').LastWriteTime -or ($headers | Where-Object { $_.LastWriteTime -gt (Get-Item '%OBJECT%').LastWriteTime })) { exit 1 }"
if not errorlevel 1 exit /b 0

echo Compiling %SOURCE%...
%CXX% -std=c++17 -Wall -Wextra -pedantic -Iheader -c "%SOURCE%" -o "%OBJECT%"
if errorlevel 1 exit /b 1
exit /b 0

:build_failed
echo Compilation failed.
popd
exit /b 1