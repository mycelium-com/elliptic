#include <string.h>

#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

#include "hmac_sha2.h"
#include "hmac_sha3.h"

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

int elliptic_hd_export_pub(EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]) {
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

int elliptic_hd_export_priv(EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]) {
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
