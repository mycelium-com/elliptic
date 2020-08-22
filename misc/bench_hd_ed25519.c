#include "elliptic.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

int main() {
    uint8_t seed[32] = {0xE9,0x87,0x3D,0x79,0xC6,0xD8,0x7D,0xC0,0xFB,0x6A,0x57,0x78,0x63,0x33,0x89,0xF4,0x45,0x32,0x13,0x30,0x3D,0xA6,0x1F,0x20,0xBD,0x67,0xFC,0x23,0x3A,0xA3,0x32,0x62};
    
    const unsigned int num_keys = 100000;

    unsigned int i;
    EllipticHDContext ctx_prv_root;
    EllipticHDContext ctx_pub_root;
    EllipticHDContext ctx_prv_child;
    EllipticHDContext ctx_pub_child;

    clock_t tic;
    clock_t toc;
    double elapsed;

    uint8_t binary_hd[BIP32_EXTKEY_SIZE] = {0};

    if (elliptic_hd_init(&ctx_prv_root, EllipticED25519, seed, sizeof(seed))) {
        elliptic_hd_neuter(&ctx_prv_root, &ctx_pub_root);

        elliptic_hd_export_priv(&ctx_prv_root, binary_hd);
        printf("Binary xpriv (root): ");
        print(&binary_hd[0], sizeof(binary_hd));
        memset(&binary_hd[0], 0, BIP32_EXTKEY_SIZE);
        printf("\n");

        elliptic_hd_export_pub(&ctx_pub_root, binary_hd);
        printf("Binary xpub: (root): ");
        print(&binary_hd[0], sizeof(binary_hd));
        memset(&binary_hd[0], 0, BIP32_EXTKEY_SIZE);
        printf("\n");
    }
    else {
        printf("elliptic_hd_init failed\n");
        return -1;
    }

    printf("Deriving %d private keys...\n", num_keys);

    // Benchmark start
    tic = clock();

    for(i = 0; i < num_keys; ++i) {
        if (!elliptic_hd_derive(&ctx_prv_root, &ctx_prv_child, i, 1)) {
            continue;
        }
    }

    // Benchmark end
    toc = clock();
    elapsed = (double)(toc - tic) / CLOCKS_PER_SEC;

    printf("Elapsed: %f seconds (%f keys/s)\n", elapsed, num_keys / elapsed);

    printf("Deriving %d public keys...\n", num_keys);

    // Benchmark start
    tic = clock();

    for(i = 0; i < num_keys; ++i) {
        if (!elliptic_hd_derive(&ctx_pub_root, &ctx_pub_child, i, 0)) {
            continue;
        }
    }

    // Benchmark end
    toc = clock();
    elapsed = (double)(toc - tic) / CLOCKS_PER_SEC;

    printf("Elapsed: %f seconds (%f keys/s)\n", elapsed, num_keys / elapsed);
}

