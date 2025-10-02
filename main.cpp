// main.cpp
// WM-Bus / OMS Volume 2 - AES-128-CBC example decryption (reference solution)
// Build: see README.md (uses OpenSSL libcrypto)
// Author: generated for assignment (uses OMS Vol2 rules for IV construction)

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>

// Helper: remove non-hex chars (newlines, spaces) and to-lower
static std::string sanitizeHex(const std::string &s){
    std::string out;
    out.reserve(s.size());
    for(char c: s){
        if(std::isxdigit((unsigned char)c)) out.push_back(std::tolower((unsigned char)c));
    }
    // if odd length -> drop last nibble (robustness)
    if(out.size() % 2) out.pop_back();
    return out;
}

static std::vector<uint8_t> hexToBytes(const std::string &hex){
    std::string s = sanitizeHex(hex);
    std::vector<uint8_t> out;
    out.reserve(s.size()/2);
    for(size_t i=0;i+1<s.size(); i+=2){
        uint8_t hi = (uint8_t)std::stoi(s.substr(i,1), nullptr, 16);
        uint8_t lo = (uint8_t)std::stoi(s.substr(i+1,1), nullptr, 16);
        out.push_back((hi<<4) | lo);
    }
    return out;
}

static std::string bytesToHex(const std::vector<uint8_t> &b){
    std::ostringstream os;
    for(auto v: b) os << std::hex << std::setfill('0') << std::setw(2) << (int)v;
    return os.str();
}

static std::string bytesToAscii(const std::vector<uint8_t> &b){
    std::string s;
    for(auto c: b){
        if(c >= 32 && c <= 126) s.push_back((char)c);
        else s.push_back('.');
    }
    return s;
}

// Remove TPL padding (OMS uses TPL padding value 0x2F — see spec note). We trim trailing 0x2F bytes.
// If not present, we try to trim trailing nulls or common padding.
static void trimOmsPadding(std::vector<uint8_t> &plain){
    // prefer to strip 0x2F
    while(!plain.empty() && plain.back() == 0x2F) plain.pop_back();
    // fallback: strip 0x00
    while(!plain.empty() && plain.back() == 0x00) plain.pop_back();
}

// AES-128-CBC decrypt (no automatic padding in OpenSSL; we manage padding manually)
static bool aes128_cbc_decrypt(const std::vector<uint8_t> &cipher,
                               const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &iv,
                               std::vector<uint8_t> &out_plain,
                               std::string &errstr)
{
    if(key.size() != 16){ errstr = "Key length != 16 bytes"; return false; }
    if(iv.size() != 16){ errstr = "IV length != 16 bytes"; return false; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){ errstr = "EVP_CIPHER_CTX_new failed"; return false; }

    bool ok = false;
    do {
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data())){
            errstr = "EVP_DecryptInit_ex failed"; break;
        }
        // disable OpenSSL padding - OMS uses specific TPL padding (0x2F)
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        // ciphertext length must be multiple of 16 when padding disabled
        if(cipher.size() % 16 != 0){
            errstr = "Ciphertext length is not a multiple of 16 bytes (block size).";
            break;
        }

        out_plain.resize(cipher.size());
        int len = 0;
        int outl = 0;
        if(1 != EVP_DecryptUpdate(ctx, out_plain.data(), &len, cipher.data(), (int)cipher.size())){
            errstr = "EVP_DecryptUpdate failed";
            break;
        }
        outl = len;
        if(1 != EVP_DecryptFinal_ex(ctx, out_plain.data()+len, &len)){
            // NOTE: when padding is disabled, EVP_DecryptFinal_ex may still succeed for exact-blocked data.
            // If it fails, still try to continue; but report error.
            // We'll not treat this as fatal in all cases, but signal in errstr.
            // For now, only accept exact successful final if len==0 or final succeeded.
            // Keep outl as is.
            // We'll still accept the output we have so far by truncating to outl.
            // Set out_plain size to outl.
            out_plain.resize(outl);
            // not ok, but still return the available plaintext
            errstr = "EVP_DecryptFinal_ex failed (maybe padding); returning partial plaintext.";
            ok = true;
            break;
        } else {
            outl += len;
            out_plain.resize(outl);
            ok = true;
        }
    } while(false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(){
    // --- CONFIG: key + message from assignment (raw hex pasted into the string) ---
    const std::string key_hex = "4255794d3dccfd46953146e701b7db68";
    const std::string msg_hex =
R"(a144c5142785895070078c20607a9d00902537ca231fa2da5889Be8df367
3ec136aeBfB80d4ce395Ba98f6B3844a115e4Be1B1c9f0a2d5ffBB92906aa388deaa
82c929310e9e5c4c0922a784df89cf0ded833Be8da996eB5885409B6c9867978dea
24001d68c603408d758a1e2B91c42eBad86a9B9d287880083BB0702850574d7B51
e9c209ed68e0374e9B01feBfd92B4cB9410fdeaf7fB526B742dc9a8d0682653)";

    std::vector<uint8_t> key = hexToBytes(key_hex);
    std::vector<uint8_t> raw = hexToBytes(msg_hex);

    if(raw.size() < 12){
        std::cerr << "Raw message too short after parsing hex. Got " << raw.size() << " bytes.\n";
        return 1;
    }

    // L-field is first byte (length). M-Bus long-format: byte0 = L, byte1=C, byte2..9 = address (8 bytes).
    uint8_t L = raw[0];
    std::cout << "Parsed raw length: " << raw.size() << " bytes. L-field (declared length) = 0x"
              << std::hex << std::setw(2) << std::setfill('0') << (int)L << std::dec << "\n";

    // compute where the user data starts in typical wM-Bus frame
    size_t idx_start_user_data = 1 /*L*/ + 1 /*C*/ + 8 /*A*/ + 1 /*CI*/;
    if(raw.size() <= idx_start_user_data){
        std::cerr << "Message too short to contain user data. Expected start at " << idx_start_user_data << "\n";
        return 1;
    }

    // user_data_len = L - 3 (L counts bytes after L including C,A,CI)
    size_t user_data_len = 0;
    if(L >= 3) user_data_len = (size_t)L - 3;
    else user_data_len = raw.size() - idx_start_user_data; // fallback
    size_t encrypted_block_end = idx_start_user_data + user_data_len;
    if(encrypted_block_end > raw.size()) encrypted_block_end = raw.size();

    std::vector<uint8_t> ciphertext(raw.begin() + idx_start_user_data, raw.begin() + encrypted_block_end);
    std::cout << "User data length (declared) = " << user_data_len << " bytes. Extracted ciphertext length = " << ciphertext.size() << " bytes.\n";

    // build IV = address (8 bytes: raw[2..9]) + 8 bytes AccessNo (repeated)
    std::vector<uint8_t> iv(16, 0);
    std::copy(raw.begin() + 2, raw.begin() + 10, iv.begin()); // bytes 2..9 (8 bytes)
    uint8_t accessNo = 0x00;
    size_t access_byte_index = idx_start_user_data + 8; // AccessNo is the 9th byte within user data (fixed header details)
    if(access_byte_index < raw.size()){
        accessNo = raw[access_byte_index];
        std::cout << "AccessNo (candidate) read from message at index " << access_byte_index << " = 0x"
                  << std::hex << std::setw(2) << std::setfill('0') << (int)accessNo << std::dec << "\n";
    } else {
        std::cout << "AccessNo not found in message (index out of range). Will try fallback IVs.\n";
    }
    for(size_t i=8;i<16;i++) iv[i] = accessNo;

    std::cout << "Constructed IV (addr + accessNo*8): " << bytesToHex(iv) << "\n";
    std::cout << "Key (hex): " << bytesToHex(key) << "\n";

    // For decryption, ciphertext length must be multiple of 16. We use the largest multiple-of-16 prefix.
    size_t usable_len = (ciphertext.size() / 16) * 16;
    if(usable_len == 0){
        std::cerr << "No usable (16-byte aligned) ciphertext to decrypt.\n";
        return 1;
    }
    std::vector<uint8_t> cipher_block(ciphertext.begin(), ciphertext.begin() + usable_len);

    // Try decryption with IV built from AccessNo
    std::vector<uint8_t> plain;
    std::string err;
    bool ok = aes128_cbc_decrypt(cipher_block, key, iv, plain, err);
    if(!ok){
        std::cerr << "Decrypt attempt (accessNo) failed: " << err << "\n";
    } else {
        trimOmsPadding(plain);
        std::cout << "\n--- Decrypted (using AccessNo repeat) ---\n";
        std::cout << "Plaintext (hex): " << bytesToHex(plain) << "\n";
        std::cout << "Plaintext (ASCII): " << bytesToAscii(plain) << "\n";
    }

    // Try fallback IV: last 8 bytes = zeros (some examples use 0x00 bytes)
    std::vector<uint8_t> iv_zero = iv;
    for(size_t i=8;i<16;i++) iv_zero[i]=0;
    std::vector<uint8_t> plain2;
    std::string err2;
    bool ok2 = aes128_cbc_decrypt(cipher_block, key, iv_zero, plain2, err2);
    if(ok2){
        trimOmsPadding(plain2);
        std::cout << "\n--- Decrypted (using last8 = 00) ---\n";
        std::cout << "Plaintext (hex): " << bytesToHex(plain2) << "\n";
        std::cout << "Plaintext (ASCII): " << bytesToAscii(plain2) << "\n";
    } else {
        std::cout << "\nFallback decrypt (last8=00) failed: " << err2 << "\n";
    }

    // Additional helpful hint to user:
    std::cout << "\nNote: OMS examples build IV = (8-byte address) || (8-byte AccessNo repeated).\n";
    std::cout << "If results are garbage, try verifying which part of the user data is encrypted (some frames have partial encryption)\n";
    std::cout << "and make sure AccessNo location (we assumed user-data offset + 8) is correct for this particular telegram.\n";

    return 0;
}
