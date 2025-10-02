# wmbus-oms-decrypt

Reference implementation for decrypting **Wireless M-Bus / OMS Volume 2** telegrams using **AES-128-CBC** with IV construction and padding handling.  
Built in C++ with OpenSSL.

## Features
- Parses raw wM-Bus telegram (hex string).
- Extracts L, C, A fields and user data.
- Constructs the IV according to OMS Annex N (address + AccessNo).
- Decrypts with AES-128-CBC (OpenSSL).
- Handles OMS TPL padding (0x2F) and ASCII output.
- Provides diagnostics (key, IV, lengths, etc.).

## Requirements
- CMake (>= 3.10)
- OpenSSL library
- C++17 compiler

## Build & Run
```bash
# install dependencies (Ubuntu example)
sudo apt install build-essential cmake libssl-dev

# clone repo
git clone https://github.com/<your-username>/wmbus-oms-decrypt.git
cd wmbus-oms-decrypt

# build
mkdir build && cd build
cmake ..
make

# run
./wmbus_decrypt
