# Crypto primitives wrapper

### What is this?

It's a ECC primitives abstraction library.

* Provides abstract API for underlying ECC cryptography.
* Support for operations with ED25519 and secp256k1 curves.
* Provides hierarchical deterministic key derivation functionality for ED25519 and secp256k1.
* Both private and public derivation modes are supported.

### API

Two separate sets of API functions are defined for ECC and HD key operations.

#### ECDSA operations

```c
/*
 * ECC context structure
 */
typedef struct EllipticContext {
    /*
     * Underlying curve identifier
     *
     *  EllipticInvalid   0
     *  EllipticED25519   1
     *  EllipticSecp256K1 2
     */
    int EllipticType;
    
    /*
     * Flag for the context type.
     *
     * Signing and verification context   1
     * Verification context               0
     */
    int HasPrivate;
    
    /*
     * Private key bytes
     */
    uint8_t PrivateKey[32];
    
    /*
     * Public key bytes
     *
     * Notes: 
     *   secp256k1 keys are stored here in the compressed form only.
     *   ed25519 keys are always prefixed with 0x03 byte.
     */
    uint8_t PublicKey[33];
} EllipticContext;
```

```c
/*
 * Initialize ECC context with either private or the public key.
 */
int elliptic_init(EllipticContext *ctx, int type, const uint8_t *key, const uint8_t *public_key);
```

```c
/*
 * Sign digest using provided ECC context.
 */
int elliptic_sign(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, uint8_t *signature);
```

```c
/*
 * Verify signature using provided ECC context.
 */
int elliptic_verify(EllipticContext *ctx, const uint8_t *digest, size_t digest_size, const uint8_t *signature, size_t signature_size);
```

#### HD key operations

```c
/*
 * HD context structure
 */
typedef struct EllipticHDContext {
    /*
     * Number of consequent parents for this HD node.
     */
    unsigned char nDepth;

    /*
     * Parent public key fingerprint.
     */
    unsigned char vchFingerprint[4];
    
    /*
     * Child index
     */
    unsigned int nChild;
    
    /*
     * Chain code, essentially a second half of BIP32 hash
     */
    unsigned char chaincode[32];
    
    /*
     * ECC context
     */
    EllipticContext context;
} EllipticHDContext;
```

```c
/*
 * Initialize HD context with extended public key.
 */
int elliptic_hd_import_pub(EllipticHDContext *ctx, int type, const uint8_t binary[BIP32_EXTKEY_SIZE]);
```

```c
/*
 * Initialize HD context with extended private key.
 */
int elliptic_hd_import_priv(EllipticHDContext *ctx, int type, const uint8_t binary[BIP32_EXTKEY_SIZE]);
```

```c
/*
 * Export extended public key from context.
 */
int elliptic_hd_export_pub(const EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]);
```

```c
/*
 * Export extended private key from context.
 */
int elliptic_hd_export_priv(const EllipticHDContext *ctx, uint8_t binary[BIP32_EXTKEY_SIZE]);
```

```c
/*
 * Initialization of new HD key derivation context with given seed data.
 */
int elliptic_hd_init(EllipticHDContext *ctx, int type, const uint8_t *seed, size_t seed_len);
```

```c
/*
 * Derive children HD context.
 */
int elliptic_hd_derive(const EllipticHDContext *ctx, EllipticHDContext *child_ctx, unsigned int nChild, int priv);
```

```c
/*
 * Initialize new context with a copy of public data.
 */
void elliptic_hd_neuter(const EllipticHDContext *ctx, EllipticHDContext *child_ctx);
```
