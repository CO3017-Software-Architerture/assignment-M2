The verifier requires a C++17 compiler and the libsodium development package.

On Windows with MinGW and libsodium available to the compiler and linker:

```bat
run.bat PUBLIC_KEY_HEX
```

On Linux or WSL, run from the assignment directory:

```sh
mkdir -p build
g++ -std=c++17 -Wall -Wextra -pedantic -Iheader \
    src/main.cpp src/server.cpp src/Verifier.cpp src/qrgen.cpp \
    src/NonceCache.cpp src/PassbackCache.cpp -lsodium -o build/server
./build/server PUBLIC_KEY_HEX
```

Replace PUBLIC_KEY_HEX with a provisioned 32-byte Ed25519 public key encoded
as 64 hex characters. Multiple public keys can be passed. Enter one
IN or OUT scan per line, followed by a space and the decoded QR text.
The CLI writes the decision to stdout and audit messages to stderr.

Run the verifier tests with the same C++17 and libsodium setup:

```sh
g++ -std=c++17 -Wall -Wextra -pedantic -Iheader \
    tests/server_verifier.cpp src/server.cpp src/Verifier.cpp src/qrgen.cpp \
    src/NonceCache.cpp src/PassbackCache.cpp -lsodium -o build/verifier-test
./build/verifier-test
```
