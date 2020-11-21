#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

int elliptic_sign(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature) {

    // To perform signing operation, we must have private key
    if (ctx->EllipticType) {
        switch (ctx->EllipticType)
        {
        case EllipticED25519:
            ed25519_sign(signature, digest, digest_size, ctx->PrivateKey);
            return 1;
        case EllipticSecp256K1:
            secp256k1_sign(signature, digest, digest_size, ctx->PrivateKey);
            return 1;
        default:
            return 0;
        }
        return 1;
    }

    // Private key is not available
    return 0;
}
