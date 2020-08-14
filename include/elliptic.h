#ifndef ELLIPTIC_H
#define ELLIPTIC_H

#include <stdint.h>
#include <stddef.h>

// Private contexts
const int EllipticInvalid = 0;
const int EllipticED25519 = 1;
const int EllipticSecp256K1 = 2;

typedef struct EllipticContext {
    int EllipticType;
    int HasPrivate;
    uint8_t PrivateKey[32];
    uint8_t PublicKey[33];
} EllipticContext;

const unsigned int BIP32_EXTKEY_SIZE = 74;

typedef struct EllipticHDContext {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    unsigned char chaincode[32];
    EllipticContext context;
} EllipticHDContext;

#ifdef __cplusplus
extern "C" {
#endif

int elliptic_init(EllipticContext *ctx, int type, const uint8_t *key, const uint8_t *public_key);
int elliptic_sign(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature);
int elliptic_verify(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature, size_t signature_size);

int elliptic_hd_import_pub(EllipticHDContext *ctx, int type, const uint8_t binary[BIP32_EXTKEY_SIZE]);
int elliptic_hd_import_priv(EllipticHDContext *ctx, int type, const uint8_t binary[BIP32_EXTKEY_SIZE]);

int elliptic_hd_export_pub(EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]);
int elliptic_hd_export_priv(EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
