#ifndef ELLIPTIC_H
#define ELLIPTIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Private contexts
const int EllipticED25519 = 1;
const int EllipticSecp256K1 = 2;

typedef struct EllipticContext {
    int EllipticType;
    int HasPrivate;
    uint8_t PrivateKey[32];
    uint8_t PublicKey[33];
} EllipticContext;

int elliptic_init(EllipticContext *ctx, int type, const uint8_t *key, const uint8_t *public_key);
int elliptic_sign(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature);
int elliptic_verify(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature, size_t signature_size);

#ifdef __cplusplus
}
#endif

#endif
