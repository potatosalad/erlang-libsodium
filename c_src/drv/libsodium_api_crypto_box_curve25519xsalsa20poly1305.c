// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_box_curve25519xsalsa20poly1305.h"

static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, seedbytes);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, publickeybytes);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, secretkeybytes);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, beforenmbytes);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, noncebytes);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, zerobytes);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, boxzerobytes);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, macbytes);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, messagebytes_max);
static int LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305);
static int LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, open);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, open);
static int LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, seed_keypair);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, seed_keypair);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, keypair);
static int LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, beforenm);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, beforenm);
static int LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, afternm);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, afternm);
static int LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, open_afternm);
static void LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, open_afternm);

libsodium_function_t libsodium_functions_crypto_box_curve25519xsalsa20poly1305[] = {
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, seedbytes),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, publickeybytes),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, secretkeybytes),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, beforenmbytes),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, noncebytes),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, zerobytes),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, boxzerobytes),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, macbytes),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, messagebytes_max),
    LS_API_R_ARGV(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305, 4),
    LS_API_R_ARGV(crypto_box_curve25519xsalsa20poly1305, open, 4),
    LS_API_R_ARGV(crypto_box_curve25519xsalsa20poly1305, seed_keypair, 1),
    LS_API_R_ARG0(crypto_box_curve25519xsalsa20poly1305, keypair),
    LS_API_R_ARGV(crypto_box_curve25519xsalsa20poly1305, beforenm, 2),
    LS_API_R_ARGV(crypto_box_curve25519xsalsa20poly1305, afternm, 3),
    LS_API_R_ARGV(crypto_box_curve25519xsalsa20poly1305, open_afternm, 3),
    {NULL}};

/* crypto_box_curve25519xsalsa20poly1305_seedbytes/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, seedbytes);

/* crypto_box_curve25519xsalsa20poly1305_publickeybytes/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, publickeybytes);

/* crypto_box_curve25519xsalsa20poly1305_secretkeybytes/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, secretkeybytes);

/* crypto_box_curve25519xsalsa20poly1305_beforenmbytes/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, beforenmbytes);

/* crypto_box_curve25519xsalsa20poly1305_noncebytes/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, noncebytes);

/* crypto_box_curve25519xsalsa20poly1305_zerobytes/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, zerobytes);

/* crypto_box_curve25519xsalsa20poly1305_boxzerobytes/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, boxzerobytes);

/* crypto_box_curve25519xsalsa20poly1305_macbytes/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, macbytes);

/* crypto_box_curve25519xsalsa20poly1305_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_box_curve25519xsalsa20poly1305, messagebytes_max);

/* crypto_box_curve25519xsalsa20poly1305_crypto_box_curve25519xsalsa20poly1305/4 */

typedef struct LS_API_F_ARGV(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305);

static int
LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
    size_t noncebytes;
    size_t publickeybytes;
    size_t secretkeybytes;
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

    noncebytes = crypto_box_curve25519xsalsa20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_curve25519xsalsa20poly1305_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_curve25519xsalsa20poly1305_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + publickeybytes + secretkeybytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305)));
    argv->m = (const unsigned char *)(p);
    p += mlen;
    argv->n = (const unsigned char *)(p);
    p += noncebytes;
    argv->pk = (const unsigned char *)(p);
    p += publickeybytes;
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305) * argv;
    LS_API_READ_ARGV(crypto_box_curve25519xsalsa20poly1305, crypto_box_curve25519xsalsa20poly1305);

    size_t clen = argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_box_curve25519xsalsa20poly1305(c, argv->m, argv->mlen, argv->n, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_box_curve25519xsalsa20poly1305_open/4 */

typedef struct LS_API_F_ARGV(crypto_box_curve25519xsalsa20poly1305, open) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open);

static int
LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, open)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long clen;
    size_t noncebytes;
    size_t publickeybytes;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    clen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    noncebytes = crypto_box_curve25519xsalsa20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_curve25519xsalsa20poly1305_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_curve25519xsalsa20poly1305_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + noncebytes + publickeybytes + secretkeybytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open)));
    argv->c = (const unsigned char *)(p);
    p += clen;
    argv->n = (const unsigned char *)(p);
    p += noncebytes;
    argv->pk = (const unsigned char *)(p);
    p += publickeybytes;
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, open)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open) * argv;
    LS_API_READ_ARGV(crypto_box_curve25519xsalsa20poly1305, open);

    size_t mlen = argv->clen;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_curve25519xsalsa20poly1305_open(m, argv->c, argv->clen, argv->n, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_box_curve25519xsalsa20poly1305_seed_keypair/1 */

typedef struct LS_API_F_ARGV(crypto_box_curve25519xsalsa20poly1305, seed_keypair) {
    const unsigned char *seed;
} LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, seed_keypair);

static int
LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, seed_keypair) * argv;
    int type;
    int type_length;
    size_t seedbytes;
    ErlDrvSizeT x;
    void *p;

    seedbytes = crypto_box_curve25519xsalsa20poly1305_seedbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != seedbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(seedbytes + (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, seed_keypair))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, seed_keypair) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, seed_keypair)));
    argv->seed = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->seed), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, seed_keypair) * argv;
    LS_API_READ_ARGV(crypto_box_curve25519xsalsa20poly1305, seed_keypair);

    size_t publickeybytes = crypto_box_curve25519xsalsa20poly1305_publickeybytes();
    size_t secretkeybytes = crypto_box_curve25519xsalsa20poly1305_secretkeybytes();

    unsigned char pk[publickeybytes];
    unsigned char sk[secretkeybytes];

    LS_SAFE_REPLY(crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk, sk, argv->seed),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(sk), secretkeybytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
    (void)sodium_memzero(sk, secretkeybytes);
}

/* crypto_box_curve25519xsalsa20poly1305_keypair/0 */

static void
LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, keypair)
{
    size_t publickeybytes = crypto_box_curve25519xsalsa20poly1305_publickeybytes();
    size_t secretkeybytes = crypto_box_curve25519xsalsa20poly1305_secretkeybytes();

    unsigned char pk[publickeybytes];
    unsigned char sk[secretkeybytes];

    LS_SAFE_REPLY(crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(sk), secretkeybytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
    (void)sodium_memzero(sk, secretkeybytes);
}

/* crypto_box_curve25519xsalsa20poly1305_beforenm/2 */

typedef struct LS_API_F_ARGV(crypto_box_curve25519xsalsa20poly1305, beforenm) {
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, beforenm);

static int
LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, beforenm)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, beforenm) * argv;
    int skip;
    int type;
    int type_length;
    size_t publickeybytes;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    publickeybytes = crypto_box_curve25519xsalsa20poly1305_publickeybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_curve25519xsalsa20poly1305_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(publickeybytes + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, beforenm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, beforenm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, beforenm)));
    argv->pk = (const unsigned char *)(p);
    p += publickeybytes;
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, beforenm)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, beforenm) * argv;
    LS_API_READ_ARGV(crypto_box_curve25519xsalsa20poly1305, beforenm);

    size_t beforenmbytes = crypto_box_curve25519xsalsa20poly1305_beforenmbytes();
    unsigned char k[beforenmbytes];

    LS_SAFE_REPLY(crypto_box_curve25519xsalsa20poly1305_beforenm(k, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k), beforenmbytes, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(k, beforenmbytes);
}

/* crypto_box_curve25519xsalsa20poly1305_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_box_curve25519xsalsa20poly1305, afternm) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, afternm);

static int
LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, afternm)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, afternm) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
    size_t noncebytes;
    size_t beforenmbytes;
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

    noncebytes = crypto_box_curve25519xsalsa20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    beforenmbytes = crypto_box_curve25519xsalsa20poly1305_beforenmbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != beforenmbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + beforenmbytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, afternm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, afternm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, afternm)));
    argv->m = (const unsigned char *)(p);
    p += mlen;
    argv->n = (const unsigned char *)(p);
    p += noncebytes;
    argv->k = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
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
LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, afternm)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, afternm) * argv;
    LS_API_READ_ARGV(crypto_box_curve25519xsalsa20poly1305, afternm);

    size_t clen = argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_box_curve25519xsalsa20poly1305_afternm(c, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_box_curve25519xsalsa20poly1305_open_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_box_curve25519xsalsa20poly1305, open_afternm) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open_afternm);

static int
LS_API_INIT(crypto_box_curve25519xsalsa20poly1305, open_afternm)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open_afternm) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long clen;
    size_t noncebytes;
    size_t beforenmbytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    clen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    noncebytes = crypto_box_curve25519xsalsa20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    beforenmbytes = crypto_box_curve25519xsalsa20poly1305_beforenmbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != beforenmbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + noncebytes + beforenmbytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open_afternm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open_afternm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open_afternm)));
    argv->c = (const unsigned char *)(p);
    p += clen;
    argv->n = (const unsigned char *)(p);
    p += noncebytes;
    argv->k = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
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
LS_API_EXEC(crypto_box_curve25519xsalsa20poly1305, open_afternm)
{
    LS_API_F_ARGV_T(crypto_box_curve25519xsalsa20poly1305, open_afternm) * argv;
    LS_API_READ_ARGV(crypto_box_curve25519xsalsa20poly1305, open_afternm);

    size_t mlen = argv->clen;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_curve25519xsalsa20poly1305_open_afternm(m, argv->c, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}
