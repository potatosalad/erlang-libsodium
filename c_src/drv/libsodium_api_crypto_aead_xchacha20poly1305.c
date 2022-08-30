// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_aead_xchacha20poly1305.h"

static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_keybytes);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_nsecbytes);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_npubbytes);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_abytes);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_messagebytes_max);
static int LS_API_INIT(crypto_aead_xchacha20poly1305, ietf_encrypt);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_encrypt);
static int LS_API_INIT(crypto_aead_xchacha20poly1305, ietf_decrypt);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_decrypt);
static int LS_API_INIT(crypto_aead_xchacha20poly1305, ietf_encrypt_detached);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_encrypt_detached);
static int LS_API_INIT(crypto_aead_xchacha20poly1305, ietf_decrypt_detached);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_decrypt_detached);
static void LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_keygen);

libsodium_function_t libsodium_functions_crypto_aead_xchacha20poly1305[] = {
    LS_API_R_ARG0(crypto_aead_xchacha20poly1305, ietf_keybytes),
    LS_API_R_ARG0(crypto_aead_xchacha20poly1305, ietf_nsecbytes),
    LS_API_R_ARG0(crypto_aead_xchacha20poly1305, ietf_npubbytes),
    LS_API_R_ARG0(crypto_aead_xchacha20poly1305, ietf_abytes),
    LS_API_R_ARG0(crypto_aead_xchacha20poly1305, ietf_messagebytes_max),
    LS_API_R_ARGV(crypto_aead_xchacha20poly1305, ietf_encrypt, 5),
    LS_API_R_ARGV(crypto_aead_xchacha20poly1305, ietf_decrypt, 5),
    LS_API_R_ARGV(crypto_aead_xchacha20poly1305, ietf_encrypt_detached, 5),
    LS_API_R_ARGV(crypto_aead_xchacha20poly1305, ietf_decrypt_detached, 6),
    LS_API_R_ARG0(crypto_aead_xchacha20poly1305, ietf_keygen),
    {NULL}};

/* crypto_aead_xchacha20poly1305_ietf_keybytes/0 */

LS_API_GET_SIZE(crypto_aead_xchacha20poly1305, ietf_keybytes);

/* crypto_aead_xchacha20poly1305_ietf_nsecbytes/0 */

LS_API_GET_SIZE(crypto_aead_xchacha20poly1305, ietf_nsecbytes);

/* crypto_aead_xchacha20poly1305_ietf_npubbytes/0 */

LS_API_GET_SIZE(crypto_aead_xchacha20poly1305, ietf_npubbytes);

/* crypto_aead_xchacha20poly1305_ietf_abytes/0 */

LS_API_GET_SIZE(crypto_aead_xchacha20poly1305, ietf_abytes);

/* crypto_aead_xchacha20poly1305_ietf_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_aead_xchacha20poly1305, ietf_messagebytes_max);

/* crypto_aead_xchacha20poly1305_ietf_encrypt/5 */

typedef struct LS_API_F_ARGV(crypto_aead_xchacha20poly1305, ietf_encrypt) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *ad;
    unsigned long long adlen;
    const unsigned char *nsec;
    const unsigned char *npub;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt);

static int
LS_API_INIT(crypto_aead_xchacha20poly1305, ietf_encrypt)
{
    LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
    unsigned long long adlen;
    size_t ietf_nsecbytes;
    size_t ietf_npubbytes;
    size_t ietf_keybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    mlen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    adlen = (unsigned long long)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_nsecbytes = crypto_aead_xchacha20poly1305_ietf_nsecbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_nsecbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_npubbytes = crypto_aead_xchacha20poly1305_ietf_npubbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_npubbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_keybytes = crypto_aead_xchacha20poly1305_ietf_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + adlen + ietf_nsecbytes + ietf_npubbytes + ietf_keybytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt)));
    argv->m = (const unsigned char *)(p);
    p += mlen;
    if (adlen == 0) {
        argv->ad = NULL;
        argv->adlen = 0;
    } else {
        argv->ad = (const unsigned char *)(p);
        p += adlen;
    }
    if (ietf_nsecbytes == 0) {
        argv->nsec = NULL;
    } else {
        argv->nsec = (const unsigned char *)(p);
        p += ietf_nsecbytes;
    }
    argv->npub = (const unsigned char *)(p);
    p += ietf_npubbytes;
    argv->k = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (adlen == 0) {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    } else {
        if (ei_decode_binary(buffer, index, (void *)(argv->ad), (long *)&(argv->adlen)) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ietf_nsecbytes == 0) {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    } else {
        if (ei_decode_binary(buffer, index, (void *)(argv->nsec), NULL) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->npub), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_encrypt)
{
    LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt) * argv;
    LS_API_READ_ARGV(crypto_aead_xchacha20poly1305, ietf_encrypt);

    size_t ietf_abytes = crypto_aead_xchacha20poly1305_ietf_abytes();
    size_t cbytes = argv->mlen + ietf_abytes;
    unsigned char c[cbytes];
    unsigned long long clen;

    LS_SAFE_REPLY(crypto_aead_xchacha20poly1305_ietf_encrypt(c, &clen, argv->m, argv->mlen, argv->ad, argv->adlen, argv->nsec,
                                                             argv->npub, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, cbytes);
}

/* crypto_aead_xchacha20poly1305_ietf_decrypt/5 */

typedef struct LS_API_F_ARGV(crypto_aead_xchacha20poly1305, ietf_decrypt) {
    unsigned char *nsec;
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *ad;
    unsigned long long adlen;
    const unsigned char *npub;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt);

static int
LS_API_INIT(crypto_aead_xchacha20poly1305, ietf_decrypt)
{
    LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt) * argv;
    int skip;
    int type;
    int type_length;
    size_t ietf_nsecbytes;
    unsigned long long clen;
    unsigned long long adlen;
    size_t ietf_npubbytes;
    size_t ietf_keybytes;
    ErlDrvSizeT x;
    void *p;

    ietf_nsecbytes = crypto_aead_xchacha20poly1305_ietf_nsecbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_nsecbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    clen = (unsigned long long)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    adlen = (unsigned long long)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_npubbytes = crypto_aead_xchacha20poly1305_ietf_npubbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_npubbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_keybytes = crypto_aead_xchacha20poly1305_ietf_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(ietf_nsecbytes + clen + adlen + ietf_npubbytes + ietf_keybytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt)));
    if (ietf_nsecbytes == 0) {
        argv->nsec = NULL;
    } else {
        argv->nsec = (unsigned char *)(p);
        p += ietf_nsecbytes;
    }
    argv->c = (const unsigned char *)(p);
    p += clen;
    if (adlen == 0) {
        argv->ad = NULL;
        argv->adlen = 0;
    } else {
        argv->ad = (const unsigned char *)(p);
        p += adlen;
    }
    argv->npub = (const unsigned char *)(p);
    p += ietf_npubbytes;
    argv->k = (const unsigned char *)(p);

    if (ietf_nsecbytes == 0) {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    } else {
        if (ei_decode_binary(buffer, index, (void *)(argv->nsec), NULL) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (adlen == 0) {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    } else {
        if (ei_decode_binary(buffer, index, (void *)(argv->ad), (long *)&(argv->adlen)) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->npub), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_decrypt)
{
    LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt) * argv;
    LS_API_READ_ARGV(crypto_aead_xchacha20poly1305, ietf_decrypt);

    size_t abytes = crypto_aead_xchacha20poly1305_ietf_abytes();
    size_t mbytes = (abytes > argv->clen) ? argv->clen : argv->clen - abytes;
    unsigned char m[mbytes];
    unsigned long long mlen;

    LS_SAFE_REPLY(crypto_aead_xchacha20poly1305_ietf_decrypt(m, &mlen, argv->nsec, argv->c, argv->clen, argv->ad, argv->adlen,
                                                             argv->npub, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mbytes);
}

/* crypto_aead_xchacha20poly1305_ietf_encrypt_detached/5 */

typedef struct LS_API_F_ARGV(crypto_aead_xchacha20poly1305, ietf_encrypt_detached) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *ad;
    unsigned long long adlen;
    const unsigned char *nsec;
    const unsigned char *npub;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt_detached);

static int
LS_API_INIT(crypto_aead_xchacha20poly1305, ietf_encrypt_detached)
{
    LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt_detached) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
    unsigned long long adlen;
    size_t ietf_nsecbytes;
    size_t ietf_npubbytes;
    size_t ietf_keybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    mlen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    adlen = (unsigned long long)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_nsecbytes = crypto_aead_xchacha20poly1305_ietf_nsecbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_nsecbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_npubbytes = crypto_aead_xchacha20poly1305_ietf_npubbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_npubbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_keybytes = crypto_aead_xchacha20poly1305_ietf_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + adlen + ietf_nsecbytes + ietf_npubbytes + ietf_keybytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt_detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt_detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt_detached)));
    argv->m = (const unsigned char *)(p);
    p += mlen;
    if (adlen == 0) {
        argv->ad = NULL;
        argv->adlen = 0;
    } else {
        argv->ad = (const unsigned char *)(p);
        p += adlen;
    }
    if (ietf_nsecbytes == 0) {
        argv->nsec = NULL;
    } else {
        argv->nsec = (const unsigned char *)(p);
        p += ietf_nsecbytes;
    }
    argv->npub = (const unsigned char *)(p);
    p += ietf_npubbytes;
    argv->k = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (adlen == 0) {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    } else {
        if (ei_decode_binary(buffer, index, (void *)(argv->ad), (long *)&(argv->adlen)) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ietf_nsecbytes == 0) {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    } else {
        if (ei_decode_binary(buffer, index, (void *)(argv->nsec), NULL) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->npub), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_encrypt_detached)
{
    LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_encrypt_detached) * argv;
    LS_API_READ_ARGV(crypto_aead_xchacha20poly1305, ietf_encrypt_detached);

    size_t ietf_abytes = crypto_aead_xchacha20poly1305_ietf_abytes();
    size_t cbytes = argv->mlen;
    unsigned char c[cbytes];
    unsigned char mac[ietf_abytes];
    unsigned long long maclen;

    LS_SAFE_REPLY(crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, &maclen, argv->m, argv->mlen, argv->ad, argv->adlen,
                                                                      argv->nsec, argv->npub, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), cbytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(mac), maclen, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(c, cbytes);
    (void)sodium_memzero(mac, ietf_abytes);
}

/* crypto_aead_xchacha20poly1305_ietf_decrypt_detached/6 */

typedef struct LS_API_F_ARGV(crypto_aead_xchacha20poly1305, ietf_decrypt_detached) {
    unsigned char *nsec;
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *mac;
    const unsigned char *ad;
    unsigned long long adlen;
    const unsigned char *npub;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt_detached);

static int
LS_API_INIT(crypto_aead_xchacha20poly1305, ietf_decrypt_detached)
{
    LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt_detached) * argv;
    int skip;
    int type;
    int type_length;
    size_t ietf_nsecbytes;
    unsigned long long clen;
    size_t ietf_abytes;
    unsigned long long adlen;
    size_t ietf_npubbytes;
    size_t ietf_keybytes;
    ErlDrvSizeT x;
    void *p;

    ietf_nsecbytes = crypto_aead_xchacha20poly1305_ietf_nsecbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_nsecbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    clen = (unsigned long long)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_abytes = crypto_aead_xchacha20poly1305_ietf_abytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_abytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    adlen = (unsigned long long)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_npubbytes = crypto_aead_xchacha20poly1305_ietf_npubbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_npubbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    ietf_keybytes = crypto_aead_xchacha20poly1305_ietf_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != ietf_keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(ietf_nsecbytes + clen + ietf_abytes + adlen + ietf_npubbytes + ietf_keybytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt_detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt_detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt_detached)));
    if (ietf_nsecbytes == 0) {
        argv->nsec = NULL;
    } else {
        argv->nsec = (unsigned char *)(p);
        p += ietf_nsecbytes;
    }
    argv->c = (const unsigned char *)(p);
    p += clen;
    argv->mac = (const unsigned char *)(p);
    p += ietf_abytes;
    if (adlen == 0) {
        argv->ad = NULL;
        argv->adlen = 0;
    } else {
        argv->ad = (const unsigned char *)(p);
        p += adlen;
    }
    argv->npub = (const unsigned char *)(p);
    p += ietf_npubbytes;
    argv->k = (const unsigned char *)(p);

    if (ietf_nsecbytes == 0) {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    } else {
        if (ei_decode_binary(buffer, index, (void *)(argv->nsec), NULL) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->mac), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (adlen == 0) {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    } else {
        if (ei_decode_binary(buffer, index, (void *)(argv->ad), (long *)&(argv->adlen)) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->npub), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_decrypt_detached)
{
    LS_API_F_ARGV_T(crypto_aead_xchacha20poly1305, ietf_decrypt_detached) * argv;
    LS_API_READ_ARGV(crypto_aead_xchacha20poly1305, ietf_decrypt_detached);

    size_t mbytes = argv->clen;
    unsigned char m[mbytes];

    LS_SAFE_REPLY(crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, argv->nsec, argv->c, argv->clen, argv->mac, argv->ad,
                                                                      argv->adlen, argv->npub, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mbytes, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mbytes);
}

/* crypto_aead_xchacha20poly1305_ietf_keygen/0 */

static void
LS_API_EXEC(crypto_aead_xchacha20poly1305, ietf_keygen)
{
    unsigned char k[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    (void)crypto_aead_xchacha20poly1305_ietf_keygen(k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY,
                             (ErlDrvTermData)(k), crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                             ERL_DRV_TUPLE,       2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
