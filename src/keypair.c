#include "elliptic.h"
#include "ed25519.h"
#include "secp256k1.h"

#include <string.h>

int elliptic_init(EllipticContext *ctx, int type, const uint8_t *key, const uint8_t *public_key) {

    // Init as invalid context
    ctx->EllipticType = EllipticInvalid;
    ctx->HasPrivate = 0;
    memset(ctx->PublicKey, 0, sizeof(ctx->PublicKey));
    memset(ctx->PrivateKey, 0, sizeof(ctx->PrivateKey));

    // If we have private key then init signing context
    if (key != NULL) {

        // Copy private key
        memcpy(&ctx->PrivateKey, key, 32);

        // Calculate public key
        switch(type) {
            case EllipticED25519:
                ctx->PublicKey[0] = 0x03;
                myc_ed25519_get_pubkey(&ctx->PublicKey[1], key);
                break;
            case EllipticSecp256K1:
                myc_secp256k1_get_pubkey(&ctx->PublicKey[0], key);
                break;
            default:
                return 0;
        }

        ctx->EllipticType = type;
        ctx->HasPrivate = 1;

        return 1;
    }

    // If there is no private key, but public key is
    //  available, then init verification-only context
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

    // Neither public nor private key has been provided
    return 0;
}
