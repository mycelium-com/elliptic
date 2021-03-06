#ifndef ELLIPTIC_H
#define ELLIPTIC_H

#include <stdint.h>
#include <stddef.h>

// Private contexts
#define EllipticInvalid 0
#define EllipticED25519 1
#define EllipticSecp256K1 2

// Extended key size
#define BIP32_EXTKEY_SIZE 74

typedef struct EllipticContext {
    int EllipticType;
    int HasPrivate;
    uint8_t PrivateKey[32];
    uint8_t PublicKey[33];
} EllipticContext;

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

// ECDSA operations
int elliptic_init(EllipticContext *ctx, int type, const uint8_t *key, const uint8_t *public_key);
int elliptic_sign(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature);
int elliptic_verify(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, const uint8_t *signature, size_t signature_size);

// HD key context import
int elliptic_hd_import_pub(EllipticHDContext *ctx, int type, const uint8_t binary[BIP32_EXTKEY_SIZE]);
int elliptic_hd_import_priv(EllipticHDContext *ctx, int type, const uint8_t binary[BIP32_EXTKEY_SIZE]);

// HD key context export
int elliptic_hd_export_pub(const EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]);
int elliptic_hd_export_priv(const EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]);

// Initialization of new HD key derivation context
int elliptic_hd_init(EllipticHDContext *ctx, int type, const uint8_t *seed, size_t seed_len);

// Derive new HD context
int elliptic_hd_derive(const EllipticHDContext *ctx, EllipticHDContext *child_ctx, unsigned int nChild, int priv);

// Strip private key
void elliptic_hd_neuter(const EllipticHDContext *ctx, EllipticHDContext *child_ctx);

#ifdef __cplusplus
}
#endif

#endif
