# wM-Bus / OMS Volume2 - AES-128 Decrypt (Reference solution)

## Goal
Decrypt the provided wM-Bus/OMS telegram (AES-128) using the provided key and produce human-readable plaintext.

This implementation:
- parses a raw wM-Bus telegram (hex)
- extracts link-layer fields (L, C, A)
- constructs the AES IV per OMS Volume 2 (Annex N)
- decrypts using AES-128-CBC (OpenSSL)
- strips OMS/TPL padding and prints plaintext (hex + ASCII)

**Assignment file used:** (uploaded). :contentReference[oaicite:7]{index=7}

## Important OMS references
- OMS Annex N shows how the AES-CBC IV is constructed: **IV = M field + A field + 8 bytes AccessNo (LSB first)**. Example and diagram in Annex N. :contentReference[oaicite:8]{index=8}  
- Table of security profiles: which profile uses AES-CBC, which uses AES-CCM/GCM/CMAC etc. (Profile A = AES128-CBC, Profile B = AES128-CBC + CMAC, Profile D = AES128-CCM, ...). Use the profile declared in the configuration field (CF) to decide mode. :contentReference[oaicite:9]{index=9}

## How the code constructs the IV (summary)
1. Parse frame bytes.
2. Address (8 bytes) is `raw[2]` .. `raw[9]`.
3. Access Number (AccessNo) is taken from the fixed header inside the user data (we use `userdata[8]` as the AccessNo byte).
4. IV := address(8) || (AccessNo repeated 8 times). (Matches Annex N examples.) :contentReference[oaicite:10]{index=10}

## Build (Linux)
```bash
# install dependencies (Ubuntu example)
sudo apt update
sudo apt install -y build-essential cmake libssl-dev git

# build
mkdir build && cd build
cmake ..
make

# run (binary placed in build/)
./wmbus_decrypt

