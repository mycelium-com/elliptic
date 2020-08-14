#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

int elliptic_sign(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature) {
    switch (ctx->EllipticType)
    {
    case EllipticED25519Priv:
        ed25519_sign(signature, digest, digest_size, &ctx->PublicKey[1], ctx->PrivateKey);
        return 1;
    case EllipticSecp256K1Priv:
        secp256k1_sign(signature, digest, digest_size, &ctx->PublicKey[1], ctx->PrivateKey);
        return 1;
    default:
        return 0;
    }
}
