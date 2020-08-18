#include <string.h>

#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

#include "hmac_sha2.h"
#include "hmac_sha3.h"
#include "ripemd160.h"

// ED25519 key fingerprint
static void BIP32Fingerprint_ed25519(const uint8_t *public_key, uint8_t *public_key_id) {
     unsigned char tmp_hash[SHA3_256_DIGEST_LENGTH]; 

    // First 4 bytes of RIPEMD160(SHA3-256(0x03 + ed25519 public key))
    sha3_256(public_key, 33, tmp_hash);
    ripemd160(tmp_hash, sizeof(tmp_hash), public_key_id); 
}

// secp256k1 key fingerprint
static void BIP32Fingerprint_secp256k1(const uint8_t *public_key, uint8_t *public_key_id) {
     unsigned char tmp_hash[SHA256_DIGEST_SIZE]; 

    // First 4 bytes of RIPEMD160(SHA3-256(0x03 + ed25519 public key))
    sha256(public_key, 33, tmp_hash);
    ripemd160(tmp_hash, sizeof(tmp_hash), public_key_id); 
}

// ED25519 key hashing
static void BIP32Hash_SHA2(const unsigned char chainCode[32], unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64])
{
    unsigned char num[4];
    hmac_sha512_ctx hmac_ctx;

    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;

    // Calculate hmac for data and num using chain code as hash key
    hmac_sha512_init(&hmac_ctx, chainCode, 32);
    hmac_sha512_update(&hmac_ctx, &header, 1);
    hmac_sha512_update(&hmac_ctx, data, 32);
    hmac_sha512_update(&hmac_ctx, num, sizeof(num));
    hmac_sha512_final(&hmac_ctx, output, 64);
}

// secp256k1 key hashing
static void BIP32Hash_SHA3(const unsigned char chainCode[32], unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64])
{
    unsigned char num[4];
    hmac_sha3_512_ctx hmac_ctx;

    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;

    // Calculate hmac for data and num using chain code as hash key
    hmac_sha3_512_init(&hmac_ctx, chainCode, 32);
    hmac_sha3_512_update(&hmac_ctx, &header, 1);
    hmac_sha3_512_update(&hmac_ctx, data, 32);
    hmac_sha3_512_update(&hmac_ctx, num, sizeof(num));
    hmac_sha3_512_final(&hmac_ctx, output, 64);
}

int elliptic_hd_import_pub(EllipticHDContext *ctx, int type, const uint8_t binary[BIP32_EXTKEY_SIZE]) {
    ctx->nDepth = binary[0];
    memcpy(ctx->vchFingerprint, binary+1, 4);
    ctx->nChild = (binary[5] << 24) | (binary[6] << 16) | (binary[7] << 8) | binary[8];
    memcpy(ctx->chaincode, binary+9, 32);
    return elliptic_init(&ctx->context, type, NULL, binary+41);
}

int elliptic_hd_import_priv(EllipticHDContext *ctx, int type, const uint8_t binary[BIP32_EXTKEY_SIZE]) {
    ctx->nDepth = binary[0];
    memcpy(ctx->vchFingerprint, binary+1, 4);
    ctx->nChild = (binary[5] << 24) | (binary[6] << 16) | (binary[7] << 8) | binary[8];
    memcpy(ctx->chaincode, binary+9, 32);
    return elliptic_init(&ctx->context, type, binary+42, NULL);
}

int elliptic_hd_export_pub(const EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]) {
    if (ctx->context.EllipticType != EllipticInvalid) {

        // Create xpub binary representation

        // Chain depth
        binary[0] = ctx->nDepth;
        // Save key fingerprint
        memcpy(binary+1, ctx->vchFingerprint, 4);
        // Child path
        binary[5] = (ctx->nChild >> 24) & 0xFF; binary[6] = (ctx->nChild >> 16) & 0xFF;
        binary[7] = (ctx->nChild >>  8) & 0xFF; binary[8] = (ctx->nChild >>  0) & 0xFF;
        // Copy chain code
        memcpy(binary+9, ctx->chaincode, 32);
        // Public key prefix is always 0x03
        binary[41] = 0x03;
        // Copy public key
        memcpy(binary+42, ctx->context.PublicKey, 33);

        return 1;
    }

    return 0;
}

int elliptic_hd_export_priv(const EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]) {
    if (ctx->context.HasPrivate) {

        // Create xpriv binary representation
        //  Note: public key is not exported

        // Chain depth
        binary[0] = ctx->nDepth;
        // Save key fingerprint
        memcpy(binary+1, ctx->vchFingerprint, 4);
        // Child path
        binary[5] = (ctx->nChild >> 24) & 0xFF; binary[6] = (ctx->nChild >> 16) & 0xFF;
        binary[7] = (ctx->nChild >>  8) & 0xFF; binary[8] = (ctx->nChild >>  0) & 0xFF;
        // Copy chain code
        memcpy(binary+9, ctx->chaincode, 32); 
        // Private key prefix is always 0x00
        binary[41] = 0; 
        // Copy private key
        memcpy(binary+42, ctx->context.PrivateKey, 32);

        return 1;
    }

    return 0;
}

int elliptic_hd_init(EllipticHDContext *ctx, int type, const uint8_t *seed, size_t seed_len) {
    // MAC hashing keys
    static const unsigned char hashkey_ed25519[] = {'E','D','2','5','5','1','9',' ','s','e','e','d'};
    static const unsigned char hashkey_secp256k1[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};

    // Hashing contexts
    hmac_sha3_512_ctx hmac_ctx_ed25519;
    hmac_sha512_ctx hmac_ctx_secp256k1;

    // MAC result
    unsigned char key_mac[64];

    // Calculate hmac for given seed using hardcoded hash key 
    switch(type) {
        case EllipticED25519:
            hmac_sha3_512_init(&hmac_ctx_ed25519, hashkey_ed25519, sizeof(hashkey_ed25519));
            hmac_sha3_512_update(&hmac_ctx_ed25519, seed, seed_len);
            hmac_sha3_512_final(&hmac_ctx_ed25519, key_mac, sizeof(key_mac)); 
            break;
        case EllipticSecp256K1:
            hmac_sha512_init(&hmac_ctx_secp256k1, hashkey_secp256k1, sizeof(hashkey_secp256k1));
            hmac_sha512_update(&hmac_ctx_secp256k1, seed, seed_len);
            hmac_sha512_final(&hmac_ctx_secp256k1, key_mac, sizeof(key_mac)); 
            break;
        default:
            return 0;
    }

    // First part of hash is to be used as key
    elliptic_init(&ctx->context, type, key_mac, NULL);

    // Second part is used as chain code
    memcpy(ctx->chaincode, key_mac + 32, 32);

    // Root node params
    ctx->nDepth = 0;
    ctx->nChild = 0;
    memset(ctx->vchFingerprint, 0, sizeof(ctx->vchFingerprint));

    return 1;
}

int elliptic_hd_derive(const EllipticHDContext *ctx, EllipticHDContext *child_ctx, unsigned int nChild, int private) {
    unsigned int pub_offset;
    unsigned char bip32_hash[64];
    unsigned char child_tmp[33];
    int (*add_scalar)(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
    void (*BIP32Fingerprint)(const uint8_t public_key[33], uint8_t fingerprint[4]);
    void (*BIP32Hash)(const unsigned char chainCode[32], unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]);

    if ((nChild >> 31) && !ctx->context.HasPrivate) {
        // An attempt of hardened derivation without private key
        return 0;
    }

    if (private && !ctx->context.HasPrivate) {
        // An attempt of private key derivation without private key
        return 0;
    }

    switch (ctx->context.EllipticType) {
        case EllipticED25519:
            pub_offset = 1;
            add_scalar = &ed25519_add_scalar;
            BIP32Hash = &BIP32Hash_SHA3;
            BIP32Fingerprint = &BIP32Fingerprint_ed25519;
            break;
        case EllipticSecp256K1:
            pub_offset = 0;
            add_scalar = &secp256k1_add_scalar;
            BIP32Hash = &BIP32Hash_SHA2;
            BIP32Fingerprint = &BIP32Fingerprint_secp256k1;
            break;
        default:
            return 0;
    }

    // Next children
    child_ctx->nChild = ctx->nChild + 1;

    // Get key fingerprint
    (*BIP32Fingerprint)(ctx->context.PublicKey, child_ctx->vchFingerprint);

    // Derive child key
    if ((nChild >> 31) == 0) {
        // Non-hardened
        (*BIP32Hash)(ctx->chaincode, nChild, ctx->context.PublicKey[0], ctx->context.PublicKey + 1, bip32_hash);

        if (ctx->context.HasPrivate && private) {
            // Generate children private key
            //  a = n + t
            memcpy(child_tmp, ctx->context.PrivateKey, 32);
            if (!(*add_scalar)(NULL, child_tmp, bip32_hash)) {
                // Overflow?
                return 0;
            }
            // Init child ECC context
            elliptic_init(&child_ctx->context, ctx->context.EllipticType, child_tmp, NULL);
        } else {
            // Generate children public key
            // A = nB + T
            memcpy(child_tmp, ctx->context.PublicKey, 33);
            if (!(*add_scalar)(child_tmp + pub_offset, NULL, bip32_hash)) {
                // Overflow?
                return 0;
            }

            // Init child ECC context
            elliptic_init(&child_ctx->context, ctx->context.EllipticType, NULL, child_tmp);
        }

    } else {
        // Hardened
        (*BIP32Hash)(ctx->chaincode, nChild, 0, ctx->context.PrivateKey, bip32_hash);

        // Generate children private key
        //  a = n + t
        memcpy(child_tmp, ctx->context.PrivateKey, 32);
        if (!(*add_scalar)(NULL, child_tmp, bip32_hash)) {
            // Overflow?
            return 0;
        }

        // Init child ECC context
        elliptic_init(&child_ctx->context, ctx->context.EllipticType, child_tmp, NULL);
    }

    // Set chain code for child key
    memcpy(child_ctx->chaincode, bip32_hash+32, 32);

    return 1;
}

void elliptic_hd_neuter(const EllipticHDContext *ctx, EllipticHDContext *public_ctx) {
    // Copy derivation context
    public_ctx->nDepth = ctx->nDepth;
    public_ctx->nChild = ctx->nChild;
    memcpy(public_ctx->vchFingerprint, ctx->vchFingerprint, 4);
    memcpy(public_ctx->chaincode, ctx->chaincode, sizeof(ctx->chaincode));
    // Init ECC context
    elliptic_init(&public_ctx->context, ctx->context.EllipticType, NULL, ctx->context.PublicKey);
}
