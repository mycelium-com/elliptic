#include "elliptic.h"
#include <stdio.h>

void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

int main() {
    EllipticContext context;
    uint8_t hash[32] = {0x6B,0xBA,0x19,0xB2,0xA7,0x1C,0xD4,0xB2,0xA3,0x1A,0x80,0x59,0x70,0xF4,0x8C,0xD,0x87,0x71,0x39,0xF4,0xD6,0xA5,0x51,0xA4,0x3D,0x41,0x35,0xD,0x89,0x1B,0x73,0x2F};
    uint8_t signature[70] = {0};
    uint8_t private[32] = {0xE9,0x87,0x3D,0x79,0xC6,0xD8,0x7D,0xC0,0xFB,0x6A,0x57,0x78,0x63,0x33,0x89,0xF4,0x45,0x32,0x13,0x30,0x3D,0xA6,0x1F,0x20,0xBD,0x67,0xFC,0x23,0x3A,0xA3,0x32,0x62};

    printf("Private key: ");
    print(private, sizeof(private));
    printf("\n");

    printf("Signing hash: ");
    print(hash, sizeof(hash));
    printf("\n");

    if (elliptic_init(&context, EllipticSecp256K1, private, NULL)) {
        printf("Public key: ");
        print(context.PublicKey, sizeof(context.PublicKey));
        printf("\n");
    }
    else {
        printf("elliptic_init FAIL\n");
        return -1;
    }

    if (elliptic_sign(&context, hash, sizeof(hash), signature)) {
        printf("Signature: ");
        print(signature, sizeof(signature));
        printf("\n");
    } 
    else {
        printf("elliptic_sign FAIL\n");
        return -1;
    }

    if (elliptic_verify(&context, hash, sizeof(hash), signature, sizeof(signature))) {
        printf("Verify OK\n");
    } 
    else {
        printf("elliptic_verify FAIL\n");
        return -1;
    }

    return 0;
}
