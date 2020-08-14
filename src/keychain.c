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

