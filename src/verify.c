#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

int elliptic_verify(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, const uint8_t *signature, size_t signature_size) {
    // Only valid contexts may be used
    switch (ctx->EllipticType)
    {
    case EllipticED25519:
        return myc_ed25519_verify(signature, digest, digest_size, &ctx->PublicKey[1]);
    case EllipticSecp256K1:
        return myc_secp256k1_verify(signature, signature_size, digest, digest_size, &ctx->PublicKey[0]);
    default:
        return 0;
    }
}
