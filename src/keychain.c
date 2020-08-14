#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

#include <string.h>

int elliptic_init(EllipticContext *ctx, int type, const uint8_t *key, const uint8_t *public_key) {

    if (key != NULL) {
        switch(type) {
            case EllipticED25519:
                ctx->PublicKey[0] = 0x03;
                ed25519_get_pubkey(&ctx->PublicKey[1], key);
                break;
            case EllipticSecp256K1:
                secp256k1_get_pubkey(&ctx->PublicKey[0], key);
                break;
            default:
                return 0;
        }

        ctx->EllipticType = type;
        ctx->HasPrivate = 1;

        return 1;
    }

    if (public_key != NULL) {
        switch(type) {
            case EllipticED25519:
            case EllipticSecp256K1:
                memcpy(ctx->PublicKey, public_key, 33);
                break;
            default:
                return 0;
        }

        ctx->EllipticType = type;
        ctx->HasPrivate = 0;

        return 1;        
    }

    return 0;
}
