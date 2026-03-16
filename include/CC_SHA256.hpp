#include "picosha2.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

namespace conclave {

    class Crypto {
    public:
        static constexpr size_t BLOCK_SIZE = 64; // SHA256 block size is 64 bytes
        static constexpr size_t HASH_SIZE = 32;  // SHA256 output is 32 bytes

        static std::vector<uint8_t> hmac_sha256(const std::string& key, const std::string& data) {
            std::vector<uint8_t> k_bytes(BLOCK_SIZE, 0);

            // 1. Prepare the key
            if (key.length() > BLOCK_SIZE) {
                // If key is too long, hash it first
                std::vector<uint8_t> hashed_key(HASH_SIZE);
                picosha2::hash256(key.begin(), key.end(), hashed_key.begin(), hashed_key.end());
                std::copy(hashed_key.begin(), hashed_key.end(), k_bytes.begin());
            } else {
                std::copy(key.begin(), key.end(), k_bytes.begin());
            }

            // 2. Create Inner and Outer Padding
            std::vector<uint8_t> ipad(BLOCK_SIZE), opad(BLOCK_SIZE);
            for (size_t i = 0; i < BLOCK_SIZE; ++i) {
                ipad[i] = k_bytes[i] ^ 0x36;
                opad[i] = k_bytes[i] ^ 0x5c;
            }

            // 3. Inner Pass: Hash(ipad + data)
            std::vector<uint8_t> inner_content = ipad;
            inner_content.insert(inner_content.end(), data.begin(), data.end());
            
            std::vector<uint8_t> inner_hash(HASH_SIZE);
            picosha2::hash256(inner_content.begin(), inner_content.end(), inner_hash.begin(), inner_hash.end());

            // 4. Outer Pass: Hash(opad + inner_hash)
            std::vector<uint8_t> outer_content = opad;
            outer_content.insert(outer_content.end(), inner_hash.begin(), inner_hash.end());

            std::vector<uint8_t> final_hash(HASH_SIZE);
            picosha2::hash256(outer_content.begin(), outer_content.end(), final_hash.begin(), final_hash.end());

            return final_hash;
        }

        // Constant-time comparison to prevent timing attacks
        static bool verify(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
            if (a.size() != b.size()) return false;
            uint8_t result = 0;
            for (size_t i = 0; i < a.size(); ++i) {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }
    };
}