#include "elliptic.h"

#include <stdio.h>

void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}


int main() {
    uint8_t seed[32] = {0xE9,0x87,0x3D,0x79,0xC6,0xD8,0x7D,0xC0,0xFB,0x6A,0x57,0x78,0x63,0x33,0x89,0xF4,0x45,0x32,0x13,0x30,0x3D,0xA6,0x1F,0x20,0xBD,0x67,0xFC,0x23,0x3A,0xA3,0x32,0x62};
    
    int i;
    EllipticHDContext ctx;
    EllipticHDContext child;
    const uint8_t binary_hd[BIP32_EXTKEY_SIZE];

    if (elliptic_hd_init(&ctx, EllipticSecp256K1, seed, sizeof(seed))) {
        elliptic_hd_export_priv(&ctx, binary_hd);
        printf("Binary xpriv (0): ");
        print(binary_hd, sizeof(binary_hd));
        elliptic_hd_export_pub(&ctx, binary_hd);
        printf("Binary xpub: (0): ");
        print(binary_hd, sizeof(binary_hd));
    }

    for(i = 0; i < 10; ++i) {
        if (elliptic_hd_derive(&ctx, &child, i)) {
            elliptic_hd_export_priv(&ctx, binary_hd);
            printf("Binary xpriv (0/%d): ", i);
            print(binary_hd, sizeof(binary_hd));
            elliptic_hd_export_pub(&ctx, binary_hd);
            printf("Binary xpub (0/%d): ", i);
            print(binary_hd, sizeof(binary_hd));
        }
        else {
            printf("elliptic_hd_derive failed\n");
            continue;
//            return -1;
        }
    }

}
