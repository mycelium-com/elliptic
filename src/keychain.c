#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

#include <string.h>

int elliptic_init(EllipticContext *ctx, int type, const uint8_t *key) {
    ctx->EllipticType = type;

    switch (type)
    {
    case EllipticED25519Priv:
        ctx->PublicKey[0] = 0x03;
        ed25519_get_pubkey(&ctx->PublicKey[1], key);
        break;
    case EllipticSecp256K1Priv:
        secp256k1_get_pubkey(&ctx->PublicKey[0], key);
        break;
    case EllipticED25519Pub:
    case EllipticSecp256K1Pub:
        memcpy(ctx->PublicKey, key, 33);
        break;

    default:
        return 0;
    }

    return 1;
}
