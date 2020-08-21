#ifndef ED25519_HD_H
#define ED25519_HD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int ed25519_init_seed(const uint8_t *seed, int seed_len, uint8_t *private_key, uint8_t *chaincode, uint8_t *kL, uint8_t *kR);
int ed25519_derive_private(const uint8_t *chainCode, unsigned int nChild, const uint8_t *public_key, const uint8_t *kL, const uint8_t *kR, uint8_t *child_kL, uint8_t *child_kR, uint8_t *childCode);
int ed25519_derive_public(const uint8_t *chainCode, unsigned int nChild, const uint8_t *public_key, const uint8_t *kL, const uint8_t *kR, uint8_t *child_public_key, uint8_t *childCode);

#ifdef __cplusplus
}
#endif

#endif
