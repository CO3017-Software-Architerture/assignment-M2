setlocal
set "CXX=g++"
set "OUTPUT=main.exe"
%CXX% -std=c++17 -Wall -Wextra -pedantic main.cpp qrgen.cpp -o %OUTPUT%
if errorlevel 1 (
    echo Compilation failed.
    exit /b 1
)

%OUTPUT%
exit /b %errorlevel%