#include <string.h>

#include "elliptic.h"
#include "ed25519.h"
#include "ge.h"

#include "hmac_sha3.h"
#include "ripemd160.h"

inline static int read(x,y) {
    return ((0u == (x & (1<<y)))?0u:1u);
}

static void multiply(uint8_t *dst, const uint8_t *src, int bytes){
	int i;
	uint8_t prev_acc = 0;
	for (i = 0; i < bytes; i++) {
		dst[i] = (src[i] << 3) + (prev_acc & 0x7);
		prev_acc = src[i] >> 5;
	}
	dst[bytes] = src[bytes-1] >> 5;
}

static void add_256bits(uint8_t *dst, const uint8_t *src1, const uint8_t *src2){
	int i; uint8_t carry = 0;
	for (i = 0; i < 32; i++) {
		uint8_t a = src1[i];
		uint8_t b = src2[i];
		uint16_t r = (uint16_t) a + (uint16_t) b + (uint16_t) carry;
		dst[i] = r & 0xff;
		carry = (r >= 0x100) ? 1 : 0;
	}
}

static void scalar_add(const uint8_t *src1, const uint8_t *src2, uint8_t *res){
    uint16_t r = 0; int i;
    for (i = 0; i < 32; i++) {
	    r = (uint16_t) src1[i] + (uint16_t) src2[i] + r;
	    res[i] = (uint8_t) r;
	    r >>= 8;
    }
}

// ed25519 key fingerprint
static void BIP32Fingerprint(const uint8_t *public_key, uint8_t *public_key_id) {
     unsigned char tmp_hash[SHA3_256_DIGEST_LENGTH]; 

    // First 4 bytes of RIPEMD160(SHA3-256(0x03 + public key))
    sha3_256(public_key, 33, tmp_hash);
    ripemd160(tmp_hash, sizeof(tmp_hash), public_key_id); 
}

// ed25519 key hashing
static void BIP32Hash(const unsigned char chainCode[32], unsigned int nChild, unsigned char header, const uint8_t *data1, int data1_length, const uint8_t *data2, int data2_length, unsigned char output[64])
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
    if (data1 != NULL) {
        hmac_sha3_512_update(&hmac_ctx, data1, data1_length);
    }
    if (data2 != NULL) {
        hmac_sha3_512_update(&hmac_ctx, data2, data2_length);
    }
    hmac_sha3_512_update(&hmac_ctx, num, sizeof(num));
    hmac_sha3_512_final(&hmac_ctx, output, 64);
}

int ed25519_init_seed(const uint8_t *seed, int seed_len, uint8_t *private_key, uint8_t *chaincode, uint8_t *kL, uint8_t *kR) {
    const unsigned char hashkey_ed25519[] = {'E','D','2','5','5','1','9',' ','s','e','e','d'};
    hmac_sha3_512_ctx hmac_ctx_ed25519;

    // MAC result
    unsigned char tmp[64] = {0};

    hmac_sha3_512_init(&hmac_ctx_ed25519, hashkey_ed25519, sizeof(hashkey_ed25519));
    hmac_sha3_512_update(&hmac_ctx_ed25519, seed, seed_len);
    hmac_sha3_512_final(&hmac_ctx_ed25519, tmp, sizeof(tmp));

    // checking the private key condition
	if(read(tmp[0], 5) != 0) {
        return 0;
    }

    // Make it real ED25519 private key
    tmp[0] &= 248;
    tmp[31] &= 63;
    tmp[31] |= 64;

    // Export left and right parts
    memcpy(kL, tmp, 32);
    memcpy(kR, tmp + 32, 32);
    
    // Make chain code
    hmac_sha3_512_init(&hmac_ctx_ed25519, hashkey_ed25519, sizeof(hashkey_ed25519));
    hmac_sha3_512_update(&hmac_ctx_ed25519, kL, sizeof(kL));
    hmac_sha3_512_update(&hmac_ctx_ed25519, kR, sizeof(kR));
    hmac_sha3_512_final(&hmac_ctx_ed25519, tmp, sizeof(tmp));
    memcpy(chaincode, tmp, 32);

    return 1;
}

int ed25519_derive_private(const uint8_t *chainCode, unsigned int nChild, const uint8_t *public_key, const uint8_t *kL, const uint8_t *kR, uint8_t *child_kL, uint8_t *child_kR, uint8_t *childCode) {
    uint8_t tmp[64];

    uint8_t zL[32] = {0};
    uint8_t zR[32] = {0};

    uint8_t zl8[32] = {0};
	uint8_t res_key[32] = {0};

    // Derive intermediate values
    if ((nChild >> 31) == 0) {
        // Non-hardened
        BIP32Hash(chainCode, nChild, 2, public_key, 32, NULL, 0, tmp);
    }
    else {
        // Hardened
        BIP32Hash(chainCode, nChild, 0, kL, 32, kR, 32, tmp);
    }

    // Init zL and zR
    memcpy(zL, tmp, 28);
    memcpy(zR, tmp + 32, 32);

    /* Kl = 8*Zl + parent(kL) */
    multiply(zl8, zL, 32);
    scalar_add(zl8, kL, res_key);
    memcpy(child_kL, res_key, 32);

	/* Kr = Zr + parent(K)r */
    memset(res_key, 0, 32);
    add_256bits(res_key, zR, kR);
    memcpy(child_kR, res_key, 32);

    // Generate chain code
    if ((nChild >> 31) == 0) {
        // Non-hardened
        BIP32Hash(chainCode, nChild, 3, public_key, 32, NULL, 0, tmp);
    }
    else {
        // Hardened
        BIP32Hash(chainCode, nChild, 1, kL, 32, kR, 32, tmp);
    }

    memcpy(childCode, tmp, 32);

    return 1;
}

int ed25519_derive_public(const uint8_t *chainCode, unsigned int nChild, const uint8_t *public_key, const uint8_t *kL, const uint8_t *kR, uint8_t *child_public_key, uint8_t *childCode) {
    uint8_t tmp[64];

    uint8_t zL[32] = {0};
    uint8_t zR[32] = {0};
    uint8_t zl8[32] = {0};

    if ((nChild >> 31) && (kL == NULL || kR == NULL)) {
        // An attempt of hardened derivation without providing the private key data
        return 0;
    }

    // Derive intermediate values
    if ((nChild >> 31) == 0) {
        // Non-hardened
        BIP32Hash(chainCode, nChild, 2, public_key, 32, NULL, 0, tmp);
    }
    else {
        // Hardened
        BIP32Hash(chainCode, nChild, 0, kL, 32, kR, 32, tmp);
    }

    // Init zL and zR
    memcpy(zL, tmp, 28);
    memcpy(zR, tmp + 32, 32);

    /* Child = Parent + 8*Zl */
    multiply(zl8, zL, 32);
    ge_point_add(public_key, zl8, child_public_key);

    // Generate chain code
    if ((nChild >> 31) == 0) {
        // Non-hardened
        BIP32Hash(chainCode, nChild, 3, public_key, 32, NULL, 0, tmp);
    }
    else {
        // Hardened
        BIP32Hash(chainCode, nChild, 1, kL, 32, kR, 32, tmp);
    }

    memcpy(childCode, tmp, 32);

    return 1;
}
