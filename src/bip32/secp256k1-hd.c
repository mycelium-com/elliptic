#include <string.h>

#include "secp256k1.h"

#include "hmac_sha2.h"
#include "ripemd160.h"

// secp256k1 key fingerprint
static void BIP32Fingerprint(const uint8_t *public_key, uint8_t *public_key_id) {
     unsigned char tmp_hash[MYC_SHA256_DIGEST_SIZE]; 

    // First 4 bytes of RIPEMD160(SHA256(public key))
    myc_sha256(public_key, 33, tmp_hash);
    myc_ripemd160(tmp_hash, sizeof(tmp_hash), tmp_hash);
    memcpy(public_key_id, tmp_hash, 4);
}

// secp256k1 key hashing
static void BIP32Hash(const unsigned char chainCode[32], unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64])
{
    unsigned char num[4];
    myc_hmac_sha512_ctx hmac_ctx;

    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;

    // Calculate hmac for data and num using chain code as hash key
    myc_hmac_sha512_init(&hmac_ctx, chainCode, 32);
    myc_hmac_sha512_update(&hmac_ctx, &header, 1);
    myc_hmac_sha512_update(&hmac_ctx, data, 32);
    myc_hmac_sha512_update(&hmac_ctx, num, sizeof(num));
    myc_hmac_sha512_final(&hmac_ctx, output, 64);
}

void secp256k1_init_seed(const uint8_t *seed, size_t seed_len, uint8_t *private_key, uint8_t *chaincode) {
    const unsigned char hashkey_secp256k1[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    myc_hmac_sha512_ctx hmac_ctx_secp256k1;

    // MAC result
    unsigned char key_mac[64];

    myc_hmac_sha512_init(&hmac_ctx_secp256k1, hashkey_secp256k1, sizeof(hashkey_secp256k1));
    myc_hmac_sha512_update(&hmac_ctx_secp256k1, seed, seed_len);
    myc_hmac_sha512_final(&hmac_ctx_secp256k1, key_mac, sizeof(key_mac));

    // First part is used as master private key
    memcpy(private_key, key_mac, 32);

    // Second part is used as chain code
    memcpy(chaincode, key_mac + 32, 32);
}

int secp256k1_derive_priv(const uint8_t *chain_code, const uint8_t *public_key, const uint8_t *private_key, uint8_t *child_fingerprint, uint8_t *child_code, uint8_t *child_key, unsigned int nChild) {

    unsigned char bip32_hash[64];

    // Get key fingerprint
    BIP32Fingerprint(public_key, child_fingerprint);

    // Derive child key
    if ((nChild >> 31) == 0) {
        // Non-hardened
        BIP32Hash(chain_code, nChild, *public_key, public_key + 1, bip32_hash);
    } else {
        // Hardened
        BIP32Hash(chain_code, nChild, 0, private_key, bip32_hash);
    }

    // Generate children private key
    //  a = n + t
    memcpy(child_key, private_key, 32);
    if (!myc_secp256k1_add_scalar(NULL, child_key, bip32_hash)) {
        // Overflow?
        return 0;
    }

    // Set chain code for child key
    memcpy(child_code, bip32_hash+32, 32);

    return 1;
}

int secp256k1_derive_pub(const uint8_t *chain_code, const uint8_t *public_key, uint8_t *child_fingerprint, uint8_t *child_code, uint8_t *child_key, unsigned int nChild) {
    
    unsigned char bip32_hash[64];

    if (nChild >> 31) {
        // An attempt of hardened derivation
        return 0;
    }

    // Get key fingerprint
    BIP32Fingerprint(public_key, child_fingerprint);

    // Derive child key
    BIP32Hash(chain_code, nChild, *public_key, public_key + 1, bip32_hash);

    // Generate children public key
    // A = nB + T
    memcpy(child_key, public_key, 33);
    if (!myc_secp256k1_add_scalar(child_key, NULL, bip32_hash)) {
        // Overflow?
        return 0;
    }

    // Set chain code for child key
    memcpy(child_code, bip32_hash+32, 32);

    return 1;
}
