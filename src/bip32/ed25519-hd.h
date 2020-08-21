#ifndef ED25519_HD_H
#define ED25519_HD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int ed25519_init_seed(const uint8_t *seed, int seed_len, uint8_t *private_key, uint8_t *chaincode);
int ed25519_derive_priv(const uint8_t *chainCode, const uint8_t *public_key, const uint8_t *private_key, uint8_t *child_fingerprint, uint8_t *childCode, uint8_t *child_private_key, unsigned int nChild);
int ed25519_derive_pub(const uint8_t *chainCode, const uint8_t *public_key, uint8_t *child_fingerprint, uint8_t *childCode, uint8_t *child_public_key, unsigned int nChild);

#ifdef __cplusplus
}
#endif

#endif
