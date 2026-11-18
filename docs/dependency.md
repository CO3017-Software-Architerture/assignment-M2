The verifier requires a C++17 compiler and the libsodium development package.

The client also requires libsodium. It reads a binary Ed25519 seed containing
exactly 32 bytes, then renders a new QR on an ANSI-capable terminal every 20 seconds
and prints its text for copy/paste. `src/seedgen.cpp`
creates `private_seed/client.seed` and prints the matching public key. If the
seed already exists, it derives and prints the same public key without replacing
the seed. The seed directory is ignored by Git; do not share or commit the seed.

On Windows with MinGW and libsodium available to the compiler and linker:

```bat
run.bat
```

Build and run the seed generator from PowerShell at the repository root:

```powershell
New-Item -ItemType Directory -Force build | Out-Null
g++ -std=c++17 -Wall -Wextra -pedantic src\seedgen.cpp -lsodium -o build\seedgen.exe
.\build\seedgen.exe
```

Put the printed 64-character public key into `employee_public_keys.txt`, one
key per line. Then build and run the client:

```powershell
New-Item -ItemType Directory -Force build | Out-Null
g++ -std=c++17 -Wall -Wextra -pedantic -Iheader `
    src\client_main.cpp src\client_entry.cpp src\client.cpp src\qrgen.cpp src\qrcodegen.cpp `
    -lsodium -o build\client.exe
.\build\client.exe .\private_seed\client.seed
```

On Linux or WSL, run from the assignment directory:

```sh
mkdir -p build
g++ -std=c++17 -Wall -Wextra -pedantic -Iheader \
    src/server_main.cpp src/server.cpp src/Verifier.cpp src/qrgen.cpp \
    src/NonceCache.cpp src/PassbackCache.cpp -lsodium -o build/server
./build/server
```

Build and run the seed generator, then the client:

```sh
g++ -std=c++17 -Wall -Wextra -pedantic \
    src/seedgen.cpp -lsodium -o build/seedgen
./build/seedgen

g++ -std=c++17 -Wall -Wextra -pedantic -Iheader \
    src/client_main.cpp src/client_entry.cpp src/client.cpp src/qrgen.cpp src/qrcodegen.cpp \
    -lsodium -o build/client
./build/client private_seed/client.seed
```

The server loads `employee_public_keys.txt` in the working directory at startup.
Pass a different path as the optional argument. Use one 64-character hex
public key per line. Blank lines are ignored. Restart the server after changing
the file. Enter one IN or OUT scan per line, followed by a space and the decoded QR text.
The CLI writes the decision to stdout and audit messages to stderr.

Run the verifier tests with the same C++17 and libsodium setup:

```sh
g++ -std=c++17 -Wall -Wextra -pedantic -Iheader \
    tests/server_verifier.cpp src/server.cpp src/Verifier.cpp src/qrgen.cpp \
    src/NonceCache.cpp src/PassbackCache.cpp -lsodium -o build/verifier-test
./build/verifier-test
```

Run the client generation test:

```sh
g++ -std=c++17 -Wall -Wextra -pedantic -Iheader \
    tests/client_generation.cpp src/client.cpp src/qrgen.cpp src/qrcodegen.cpp \
    -lsodium -o build/client-test
./build/client-test
```

On Windows, use `-o build\client-test.exe` and run
`.\build\client-test.exe` from PowerShell.

The client generation test creates a temporary key in memory. It does not need
the seed file. The verifier test also creates its own temporary keys.
