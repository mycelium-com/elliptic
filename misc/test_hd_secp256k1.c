#include "elliptic.h"

#include <stdio.h>
#include <string.h>

void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

int main() {
    uint8_t seed[32] = {0xE9,0x87,0x3D,0x79,0xC6,0xD8,0x7D,0xC0,0xFB,0x6A,0x57,0x78,0x63,0x33,0x89,0xF4,0x45,0x32,0x13,0x30,0x3D,0xA6,0x1F,0x20,0xBD,0x67,0xFC,0x23,0x3A,0xA3,0x32,0x62};
    
    int i;
    EllipticHDContext ctx;
    EllipticHDContext root_pub;
    EllipticHDContext child;

    uint8_t binary_hd[BIP32_EXTKEY_SIZE] = {0};

    if (elliptic_hd_init(&ctx, EllipticSecp256K1, seed, sizeof(seed))) {
        elliptic_hd_export_priv(&ctx, binary_hd);
        printf("Binary xpriv (root): ");
        print(&binary_hd[0], sizeof(binary_hd));
        memset(&binary_hd[0], 0, BIP32_EXTKEY_SIZE);
        printf("\n");

        elliptic_hd_export_pub(&ctx, binary_hd);
        printf("Binary xpub: (root): ");
        print(&binary_hd[0], sizeof(binary_hd));
        memset(&binary_hd[0], 0, BIP32_EXTKEY_SIZE);
        printf("\n");

        elliptic_hd_neuter(&ctx, &root_pub);
    }

    printf("Private key derivation:\n");

    for(i = 0; i < 5; ++i) {
        if (elliptic_hd_derive(&ctx, &child, i, 1)) {
            elliptic_hd_export_priv(&child, binary_hd);
            printf("Binary xpriv (0/%d): ", i);
            print(&binary_hd[0], sizeof(binary_hd));
            memset(&binary_hd[0], 0, BIP32_EXTKEY_SIZE);
            printf("\n");

            elliptic_hd_export_pub(&child, binary_hd);
            printf("Binary xpub (0/%d): ", i);
            print(&binary_hd[0], sizeof(binary_hd));
            memset(&binary_hd[0], 0, BIP32_EXTKEY_SIZE);
            printf("\n");
        }
        else {
            printf("elliptic_hd_derive failed\n");
            return -1;
        }
    }

    printf("Public key derivation:\n");

    for(i = 0; i < 5; ++i) {
        if (elliptic_hd_derive(&root_pub, &child, i, 0)) {

            elliptic_hd_export_pub(&child, binary_hd);
            printf("Binary xpub (0/%d): ", i);
            print(&binary_hd[0], sizeof(binary_hd));
            memset(&binary_hd[0], 0, BIP32_EXTKEY_SIZE);
            printf("\n");
        }
        else {
            printf("elliptic_hd_derive failed\n");
            return -1;
        }
    }

}
