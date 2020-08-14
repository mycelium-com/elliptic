#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

int elliptic_verify(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature, size_t signature_size) {
    switch (ctx->EllipticType)
    {
    case EllipticED25519:
        return ed25519_verify(signature, digest, digest_size, &ctx->PublicKey[1]);
    case EllipticSecp256K1:
        return secp256k1_verify(signature, signature_size, digest, digest_size, &ctx->PublicKey[0]);
    default:
        return 0;
    }
}
