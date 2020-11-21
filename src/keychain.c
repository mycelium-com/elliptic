#include <string.h>

#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

#include "hmac_sha3.h"
#include "ripemd160.h"

#include "secp256k1-hd.h"
#include "ed25519-hd.h"

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
        // Copy public key
        memcpy(binary+41, ctx->context.PublicKey, 33);

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

    // Space for the private key
    uint8_t private_key[32];

    // Get private key and chain code 
    switch(type) {
        case EllipticSecp256K1:
            secp256k1_init_seed(seed, seed_len, private_key, ctx->chaincode);
            break;
        case EllipticED25519:
            if (!ed25519_init_seed(seed, seed_len, private_key, ctx->chaincode)) {
                return 0;
            }
            break;
        default:
            return 0;
    }

    // First part of hash is to be used as key
    elliptic_init(&ctx->context, type, private_key, NULL);

    // Root node params
    ctx->nDepth = 0;
    ctx->nChild = 0;
    memset(ctx->vchFingerprint, 0, sizeof(ctx->vchFingerprint));

    return 1;
}

static int derive_priv(const EllipticHDContext *ctx, EllipticHDContext *child_ctx, unsigned int nChild) {

    unsigned char child_tmp[32];

    switch (ctx->context.EllipticType) {
        case EllipticSecp256K1:
            if (!secp256k1_derive_priv(ctx->chaincode, ctx->context.PublicKey, ctx->context.PrivateKey, child_ctx->vchFingerprint, child_ctx->chaincode, child_tmp, nChild)) {
                return 0;
            }
            break;
        case EllipticED25519:
            if (!ed25519_derive_priv(ctx->chaincode, ctx->context.PublicKey + 1, ctx->context.PrivateKey, child_ctx->vchFingerprint, child_ctx->chaincode, child_tmp, nChild)) {
                return 0;
            }
            break;
        default:
            return 0;
    }

    // Next children
    child_ctx->nChild = nChild;
    child_ctx->nDepth = ctx->nDepth + 1;

    // Init child ECC context
    elliptic_init(&child_ctx->context, ctx->context.EllipticType, child_tmp, NULL);

    return 1;
}

static int derive_pub(const EllipticHDContext *ctx, EllipticHDContext *child_ctx, unsigned int nChild) {

    unsigned char child_tmp[33];
    const int hardened = (nChild >> 31);
    const int has_priv = ctx->context.HasPrivate;

    if (hardened && !has_priv) {
        // An attempt of hardened derivation without private key
        return 0;
    }

    switch (ctx->context.EllipticType) {
        case EllipticSecp256K1:
            if (has_priv) {
                // If we have private key then we don't need to perform excessive point operations
                if (!secp256k1_derive_priv(ctx->chaincode, ctx->context.PublicKey, ctx->context.PrivateKey, child_ctx->vchFingerprint, child_ctx->chaincode, child_tmp, nChild)) {
                    return 0;
                }

                // Compute public key
                secp256k1_get_pubkey(child_tmp, child_tmp);
            }
            else {
                // If we don't have private key then use public key
                if (!secp256k1_derive_pub(ctx->chaincode, ctx->context.PublicKey, child_ctx->vchFingerprint, child_ctx->chaincode, child_tmp, nChild)) {
                    return 0;
                }
            }

            break;
        case EllipticED25519:
            if (has_priv) {
                // If we have private key then we don't need to perform excessive point operations
                if (!ed25519_derive_priv(ctx->chaincode, ctx->context.PublicKey + 1, ctx->context.PrivateKey, child_ctx->vchFingerprint, child_ctx->chaincode, child_tmp, nChild)) {
                    return 0;
                }

                // Compute public key
                child_tmp[0] = 0x03;
                ed25519_get_pubkey(child_tmp + 1, child_tmp + 1);
            }
            else {
                // If we don't have private key then use public key
                child_tmp[0] = 0x03;
                if (!ed25519_derive_pub(ctx->chaincode, ctx->context.PublicKey + 1, child_ctx->vchFingerprint, child_ctx->chaincode, child_tmp + 1, nChild)) {
                    return 0;
                }
            }

            break;
        default:
            return 0;
    }

    // Next children
    child_ctx->nChild = nChild;
    child_ctx->nDepth = ctx->nDepth + 1;

    // Init child ECC context
    elliptic_init(&child_ctx->context, ctx->context.EllipticType, NULL, child_tmp);

    return 1;
}

int elliptic_hd_derive(const EllipticHDContext *ctx, EllipticHDContext *child_ctx, unsigned int nChild, int priv) {
    return priv ? derive_priv(ctx, child_ctx, nChild) : derive_pub(ctx, child_ctx, nChild);
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
