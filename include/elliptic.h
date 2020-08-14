#ifndef ELLIPTIC_H
#define ELLIPTIC_H

#include <stdint.h>
#include <stddef.h>

// Private contexts
const int EllipticED25519Priv = 1;
const int EllipticSecp256K1Priv = 3;

// Public contexts
const int EllipticED25519Pub = 2;
const int EllipticSecp256K1Pub = 4;

typedef struct EllipticContext {
    int EllipticType;
    uint8_t PrivateKey[32];
    uint8_t PublicKey[33];
} EllipticContext;

int elliptic_init(EllipticContext *ctx, int type, const uint8_t *key);
int elliptic_sign(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature);
int elliptic_verify(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature, size_t signature_size);

#endif
