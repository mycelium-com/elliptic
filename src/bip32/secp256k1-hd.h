#ifndef SECP256K1_HD_H
#define SECP256K1_HD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Derive secp256k1 root key and chaincode from seed
void secp256k1_init_seed(const uint8_t *seed, size_t seed_len, uint8_t *private_key, uint8_t *chaincode);
// Derive new secp256k1 private key
int secp256k1_derive_priv(const uint8_t *chain_code, const uint8_t *public_key, const uint8_t *private_key, uint8_t *child_fingerprint, uint8_t *child_code, uint8_t *child_key, unsigned int nChild);
// Derive new secp256k1 public key
int secp256k1_derive_pub(const uint8_t *chain_code, const uint8_t *public_key, uint8_t *child_fingerprint, uint8_t *child_code, uint8_t *child_key, unsigned int nChild);

#ifdef __cplusplus
}
#endif

#endif
