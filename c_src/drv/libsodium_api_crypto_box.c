// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_box.h"

static void LS_API_EXEC(crypto_box, seedbytes);
static void LS_API_EXEC(crypto_box, publickeybytes);
static void LS_API_EXEC(crypto_box, secretkeybytes);
static void LS_API_EXEC(crypto_box, noncebytes);
static void LS_API_EXEC(crypto_box, macbytes);
static void LS_API_EXEC(crypto_box, messagebytes_max);
static void LS_API_EXEC(crypto_box, primitive);
static int LS_API_INIT(crypto_box, seed_keypair);
static void LS_API_EXEC(crypto_box, seed_keypair);
static void LS_API_EXEC(crypto_box, keypair);
static int LS_API_INIT(crypto_box, easy);
static void LS_API_EXEC(crypto_box, easy);
static int LS_API_INIT(crypto_box, open_easy);
static void LS_API_EXEC(crypto_box, open_easy);
static int LS_API_INIT(crypto_box, detached);
static void LS_API_EXEC(crypto_box, detached);
static int LS_API_INIT(crypto_box, open_detached);
static void LS_API_EXEC(crypto_box, open_detached);
static void LS_API_EXEC(crypto_box, beforenmbytes);
static int LS_API_INIT(crypto_box, beforenm);
static void LS_API_EXEC(crypto_box, beforenm);
static int LS_API_INIT(crypto_box, easy_afternm);
static void LS_API_EXEC(crypto_box, easy_afternm);
static int LS_API_INIT(crypto_box, open_easy_afternm);
static void LS_API_EXEC(crypto_box, open_easy_afternm);
static int LS_API_INIT(crypto_box, detached_afternm);
static void LS_API_EXEC(crypto_box, detached_afternm);
static int LS_API_INIT(crypto_box, open_detached_afternm);
static void LS_API_EXEC(crypto_box, open_detached_afternm);
static void LS_API_EXEC(crypto_box, sealbytes);
static int LS_API_INIT(crypto_box, seal);
static void LS_API_EXEC(crypto_box, seal);
static int LS_API_INIT(crypto_box, seal_open);
static void LS_API_EXEC(crypto_box, seal_open);
static void LS_API_EXEC(crypto_box, zerobytes);
static void LS_API_EXEC(crypto_box, boxzerobytes);
static int LS_API_INIT(crypto_box, crypto_box);
static void LS_API_EXEC(crypto_box, crypto_box);
static int LS_API_INIT(crypto_box, open);
static void LS_API_EXEC(crypto_box, open);
static int LS_API_INIT(crypto_box, afternm);
static void LS_API_EXEC(crypto_box, afternm);
static int LS_API_INIT(crypto_box, open_afternm);
static void LS_API_EXEC(crypto_box, open_afternm);

libsodium_function_t libsodium_functions_crypto_box[] = {LS_API_R_ARG0(crypto_box, seedbytes),
                                                         LS_API_R_ARG0(crypto_box, publickeybytes),
                                                         LS_API_R_ARG0(crypto_box, secretkeybytes),
                                                         LS_API_R_ARG0(crypto_box, noncebytes),
                                                         LS_API_R_ARG0(crypto_box, macbytes),
                                                         LS_API_R_ARG0(crypto_box, messagebytes_max),
                                                         LS_API_R_ARG0(crypto_box, primitive),
                                                         LS_API_R_ARGV(crypto_box, seed_keypair, 1),
                                                         LS_API_R_ARG0(crypto_box, keypair),
                                                         LS_API_R_ARGV(crypto_box, easy, 4),
                                                         LS_API_R_ARGV(crypto_box, open_easy, 4),
                                                         LS_API_R_ARGV(crypto_box, detached, 4),
                                                         LS_API_R_ARGV(crypto_box, open_detached, 5),
                                                         LS_API_R_ARG0(crypto_box, beforenmbytes),
                                                         LS_API_R_ARGV(crypto_box, beforenm, 2),
                                                         LS_API_R_ARGV(crypto_box, easy_afternm, 3),
                                                         LS_API_R_ARGV(crypto_box, open_easy_afternm, 3),
                                                         LS_API_R_ARGV(crypto_box, detached_afternm, 3),
                                                         LS_API_R_ARGV(crypto_box, open_detached_afternm, 4),
                                                         LS_API_R_ARG0(crypto_box, sealbytes),
                                                         LS_API_R_ARGV(crypto_box, seal, 2),
                                                         LS_API_R_ARGV(crypto_box, seal_open, 3),
                                                         LS_API_R_ARG0(crypto_box, zerobytes),
                                                         LS_API_R_ARG0(crypto_box, boxzerobytes),
                                                         LS_API_R_ARGV(crypto_box, crypto_box, 4),
                                                         LS_API_R_ARGV(crypto_box, open, 4),
                                                         LS_API_R_ARGV(crypto_box, afternm, 3),
                                                         LS_API_R_ARGV(crypto_box, open_afternm, 3),
                                                         {NULL}};

/* crypto_box_seedbytes/0 */

LS_API_GET_SIZE(crypto_box, seedbytes);

/* crypto_box_publickeybytes/0 */

LS_API_GET_SIZE(crypto_box, publickeybytes);

/* crypto_box_secretkeybytes/0 */

LS_API_GET_SIZE(crypto_box, secretkeybytes);

/* crypto_box_noncebytes/0 */

LS_API_GET_SIZE(crypto_box, noncebytes);

/* crypto_box_macbytes/0 */

LS_API_GET_SIZE(crypto_box, macbytes);

/* crypto_box_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_box, messagebytes_max);

/* crypto_box_primitive/0 */

LS_API_GET_ATOM(crypto_box, primitive);

/* crypto_box_seed_keypair/1 */

typedef struct LS_API_F_ARGV(crypto_box, seed_keypair) {
    const unsigned char *seed;
} LS_API_F_ARGV_T(crypto_box, seed_keypair);

static int
LS_API_INIT(crypto_box, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_box, seed_keypair) * argv;
    int type;
    int type_length;
    size_t seedbytes;
    ErlDrvSizeT x;
    void *p;

    seedbytes = crypto_box_seedbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != seedbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(seedbytes + (sizeof(LS_API_F_ARGV_T(crypto_box, seed_keypair))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, seed_keypair) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, seed_keypair)));
    argv->seed = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->seed), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_box, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_box, seed_keypair) * argv;
    LS_API_READ_ARGV(crypto_box, seed_keypair);

    size_t publickeybytes = crypto_box_publickeybytes();
    size_t secretkeybytes = crypto_box_secretkeybytes();

    unsigned char pk[publickeybytes];
    unsigned char sk[secretkeybytes];

    LS_SAFE_REPLY(crypto_box_seed_keypair(pk, sk, argv->seed),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(sk), secretkeybytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
    (void)sodium_memzero(sk, secretkeybytes);
}

/* crypto_box_keypair/0 */

static void
LS_API_EXEC(crypto_box, keypair)
{
    size_t publickeybytes = crypto_box_publickeybytes();
    size_t secretkeybytes = crypto_box_secretkeybytes();

    unsigned char pk[publickeybytes];
    unsigned char sk[secretkeybytes];

    LS_SAFE_REPLY(crypto_box_keypair(pk, sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(sk), secretkeybytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
    (void)sodium_memzero(sk, secretkeybytes);
}

/* crypto_box_easy/4 */

typedef struct LS_API_F_ARGV(crypto_box, easy) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box, easy);

static int
LS_API_INIT(crypto_box, easy)
{
    LS_API_F_ARGV_T(crypto_box, easy) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + publickeybytes + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box, easy))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, easy) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, easy)));
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
LS_API_EXEC(crypto_box, easy)
{
    LS_API_F_ARGV_T(crypto_box, easy) * argv;
    LS_API_READ_ARGV(crypto_box, easy);

    size_t macbytes = crypto_box_macbytes();
    size_t clen = macbytes + argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_box_easy(c, argv->m, argv->mlen, argv->n, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_box_open_easy/4 */

typedef struct LS_API_F_ARGV(crypto_box, open_easy) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box, open_easy);

static int
LS_API_INIT(crypto_box, open_easy)
{
    LS_API_F_ARGV_T(crypto_box, open_easy) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + noncebytes + publickeybytes + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box, open_easy))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, open_easy) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, open_easy)));
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
LS_API_EXEC(crypto_box, open_easy)
{
    LS_API_F_ARGV_T(crypto_box, open_easy) * argv;
    LS_API_READ_ARGV(crypto_box, open_easy);

    size_t macbytes = crypto_box_macbytes();
    size_t mlen = argv->clen - macbytes;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_open_easy(m, argv->c, argv->clen, argv->n, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_box_detached/4 */

typedef struct LS_API_F_ARGV(crypto_box, detached) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box, detached);

static int
LS_API_INIT(crypto_box, detached)
{
    LS_API_F_ARGV_T(crypto_box, detached) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + publickeybytes + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box, detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, detached)));
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
LS_API_EXEC(crypto_box, detached)
{
    LS_API_F_ARGV_T(crypto_box, detached) * argv;
    LS_API_READ_ARGV(crypto_box, detached);

    size_t macbytes = crypto_box_macbytes();
    size_t clen = argv->mlen;
    unsigned char c[clen];
    unsigned char mac[macbytes];

    LS_SAFE_REPLY(crypto_box_detached(c, mac, argv->m, argv->mlen, argv->n, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(mac), macbytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(c, clen);
    (void)sodium_memzero(mac, macbytes);
}

/* crypto_box_open_detached/5 */

typedef struct LS_API_F_ARGV(crypto_box, open_detached) {
    const unsigned char *c;
    const unsigned char *mac;
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box, open_detached);

static int
LS_API_INIT(crypto_box, open_detached)
{
    LS_API_F_ARGV_T(crypto_box, open_detached) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long clen;
    size_t macbytes;
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

    macbytes = crypto_box_macbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != macbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + macbytes + noncebytes + publickeybytes + secretkeybytes +
                      (sizeof(LS_API_F_ARGV_T(crypto_box, open_detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, open_detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, open_detached)));
    argv->c = (const unsigned char *)(p);
    p += clen;
    argv->mac = (const unsigned char *)(p);
    p += macbytes;
    argv->n = (const unsigned char *)(p);
    p += noncebytes;
    argv->pk = (const unsigned char *)(p);
    p += publickeybytes;
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->mac), NULL) < 0) {
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
LS_API_EXEC(crypto_box, open_detached)
{
    LS_API_F_ARGV_T(crypto_box, open_detached) * argv;
    LS_API_READ_ARGV(crypto_box, open_detached);

    size_t mlen = argv->clen;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_open_detached(m, argv->c, argv->mac, argv->clen, argv->n, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_box_beforenmbytes/0 */

LS_API_GET_SIZE(crypto_box, beforenmbytes);

/* crypto_box_beforenm/2 */

typedef struct LS_API_F_ARGV(crypto_box, beforenm) {
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box, beforenm);

static int
LS_API_INIT(crypto_box, beforenm)
{
    LS_API_F_ARGV_T(crypto_box, beforenm) * argv;
    int skip;
    int type;
    int type_length;
    size_t publickeybytes;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(publickeybytes + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box, beforenm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, beforenm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, beforenm)));
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

int crypto_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk) __attribute__((warn_unused_result));

static void
LS_API_EXEC(crypto_box, beforenm)
{
    LS_API_F_ARGV_T(crypto_box, beforenm) * argv;
    LS_API_READ_ARGV(crypto_box, beforenm);

    size_t beforenmbytes = crypto_box_beforenmbytes();
    unsigned char k[beforenmbytes];

    LS_SAFE_REPLY(crypto_box_beforenm(k, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k), beforenmbytes, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(k, beforenmbytes);
}

/* crypto_box_easy_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_box, easy_afternm) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_box, easy_afternm);

static int
LS_API_INIT(crypto_box, easy_afternm)
{
    LS_API_F_ARGV_T(crypto_box, easy_afternm) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    beforenmbytes = crypto_box_beforenmbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != beforenmbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + beforenmbytes + (sizeof(LS_API_F_ARGV_T(crypto_box, easy_afternm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, easy_afternm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, easy_afternm)));
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
LS_API_EXEC(crypto_box, easy_afternm)
{
    LS_API_F_ARGV_T(crypto_box, easy_afternm) * argv;
    LS_API_READ_ARGV(crypto_box, easy_afternm);

    size_t macbytes = crypto_box_macbytes();
    size_t clen = macbytes + argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_box_easy_afternm(c, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_box_open_easy_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_box, open_easy_afternm) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_box, open_easy_afternm);

static int
LS_API_INIT(crypto_box, open_easy_afternm)
{
    LS_API_F_ARGV_T(crypto_box, open_easy_afternm) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    beforenmbytes = crypto_box_beforenmbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != beforenmbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + noncebytes + beforenmbytes + (sizeof(LS_API_F_ARGV_T(crypto_box, open_easy_afternm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, open_easy_afternm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, open_easy_afternm)));
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
LS_API_EXEC(crypto_box, open_easy_afternm)
{
    LS_API_F_ARGV_T(crypto_box, open_easy_afternm) * argv;
    LS_API_READ_ARGV(crypto_box, open_easy_afternm);

    size_t macbytes = crypto_box_macbytes();
    size_t mlen = argv->clen - macbytes;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_open_easy_afternm(m, argv->c, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_box_detached_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_box, detached_afternm) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_box, detached_afternm);

static int
LS_API_INIT(crypto_box, detached_afternm)
{
    LS_API_F_ARGV_T(crypto_box, detached_afternm) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    beforenmbytes = crypto_box_beforenmbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != beforenmbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + beforenmbytes + (sizeof(LS_API_F_ARGV_T(crypto_box, detached_afternm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, detached_afternm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, detached_afternm)));
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
LS_API_EXEC(crypto_box, detached_afternm)
{
    LS_API_F_ARGV_T(crypto_box, detached_afternm) * argv;
    LS_API_READ_ARGV(crypto_box, detached_afternm);

    size_t macbytes = crypto_box_macbytes();
    size_t clen = argv->mlen;
    unsigned char c[clen];
    unsigned char mac[macbytes];

    LS_SAFE_REPLY(crypto_box_detached_afternm(c, mac, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(mac), macbytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(c, clen);
    (void)sodium_memzero(mac, macbytes);
}

/* crypto_box_open_detached_afternm/5 */

typedef struct LS_API_F_ARGV(crypto_box, open_detached_afternm) {
    const unsigned char *c;
    const unsigned char *mac;
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_box, open_detached_afternm);

static int
LS_API_INIT(crypto_box, open_detached_afternm)
{
    LS_API_F_ARGV_T(crypto_box, open_detached_afternm) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long clen;
    size_t macbytes;
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

    macbytes = crypto_box_macbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != macbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    beforenmbytes = crypto_box_beforenmbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != beforenmbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + macbytes + noncebytes + beforenmbytes + (sizeof(LS_API_F_ARGV_T(crypto_box, open_detached_afternm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, open_detached_afternm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, open_detached_afternm)));
    argv->c = (const unsigned char *)(p);
    p += clen;
    argv->mac = (const unsigned char *)(p);
    p += macbytes;
    argv->n = (const unsigned char *)(p);
    p += noncebytes;
    argv->k = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->mac), NULL) < 0) {
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
LS_API_EXEC(crypto_box, open_detached_afternm)
{
    LS_API_F_ARGV_T(crypto_box, open_detached_afternm) * argv;
    LS_API_READ_ARGV(crypto_box, open_detached_afternm);

    size_t mlen = argv->clen;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_open_detached_afternm(m, argv->c, argv->mac, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_box_sealbytes/0 */

LS_API_GET_SIZE(crypto_box, sealbytes);

/* crypto_box_seal/2 */

typedef struct LS_API_F_ARGV(crypto_box, seal) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *pk;
} LS_API_F_ARGV_T(crypto_box, seal);

static int
LS_API_INIT(crypto_box, seal)
{
    LS_API_F_ARGV_T(crypto_box, seal) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
    size_t publickeybytes;
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

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + publickeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box, seal))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, seal) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, seal)));
    argv->m = (const unsigned char *)(p);
    p += mlen;
    argv->pk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_box, seal)
{
    LS_API_F_ARGV_T(crypto_box, seal) * argv;
    LS_API_READ_ARGV(crypto_box, seal);

    size_t sealbytes = crypto_box_sealbytes();
    size_t clen = sealbytes + argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_box_seal(c, argv->m, argv->mlen, argv->pk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_box_seal_open/3 */

typedef struct LS_API_F_ARGV(crypto_box, seal_open) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box, seal_open);

static int
LS_API_INIT(crypto_box, seal_open)
{
    LS_API_F_ARGV_T(crypto_box, seal_open) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long clen;
    size_t sealbytes;
    size_t publickeybytes;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    clen = (unsigned long long)(type_length);

    sealbytes = crypto_box_sealbytes();

    if (clen < sealbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + publickeybytes + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box, seal_open))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, seal_open) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, seal_open)));
    argv->c = (const unsigned char *)(p);
    p += clen;
    argv->pk = (const unsigned char *)(p);
    p += publickeybytes;
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
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
LS_API_EXEC(crypto_box, seal_open)
{
    LS_API_F_ARGV_T(crypto_box, seal_open) * argv;
    LS_API_READ_ARGV(crypto_box, seal_open);

    size_t sealbytes = crypto_box_sealbytes();
    size_t mlen = argv->clen - sealbytes;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_seal_open(m, argv->c, argv->clen, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_box_zerobytes/0 */

LS_API_GET_SIZE(crypto_box, zerobytes);

/* crypto_box_boxzerobytes/0 */

LS_API_GET_SIZE(crypto_box, boxzerobytes);

/* crypto_box_crypto_box/4 */

typedef struct LS_API_F_ARGV(crypto_box, crypto_box) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box, crypto_box);

static int
LS_API_INIT(crypto_box, crypto_box)
{
    LS_API_F_ARGV_T(crypto_box, crypto_box) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + publickeybytes + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box, crypto_box))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, crypto_box) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, crypto_box)));
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
LS_API_EXEC(crypto_box, crypto_box)
{
    LS_API_F_ARGV_T(crypto_box, crypto_box) * argv;
    LS_API_READ_ARGV(crypto_box, crypto_box);

    size_t clen = argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_box(c, argv->m, argv->mlen, argv->n, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_box_open/4 */

typedef struct LS_API_F_ARGV(crypto_box, open) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *pk;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_box, open);

static int
LS_API_INIT(crypto_box, open)
{
    LS_API_F_ARGV_T(crypto_box, open) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_box_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_box_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + noncebytes + publickeybytes + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_box, open))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, open) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, open)));
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
LS_API_EXEC(crypto_box, open)
{
    LS_API_F_ARGV_T(crypto_box, open) * argv;
    LS_API_READ_ARGV(crypto_box, open);

    size_t mlen = argv->clen;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_open(m, argv->c, argv->clen, argv->n, argv->pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_box_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_box, afternm) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_box, afternm);

static int
LS_API_INIT(crypto_box, afternm)
{
    LS_API_F_ARGV_T(crypto_box, afternm) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    beforenmbytes = crypto_box_beforenmbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != beforenmbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + beforenmbytes + (sizeof(LS_API_F_ARGV_T(crypto_box, afternm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, afternm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, afternm)));
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
LS_API_EXEC(crypto_box, afternm)
{
    LS_API_F_ARGV_T(crypto_box, afternm) * argv;
    LS_API_READ_ARGV(crypto_box, afternm);

    size_t clen = argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_box_afternm(c, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_box_open_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_box, open_afternm) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_box, open_afternm);

static int
LS_API_INIT(crypto_box, open_afternm)
{
    LS_API_F_ARGV_T(crypto_box, open_afternm) * argv;
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

    noncebytes = crypto_box_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    beforenmbytes = crypto_box_beforenmbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != beforenmbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + noncebytes + beforenmbytes + (sizeof(LS_API_F_ARGV_T(crypto_box, open_afternm))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_box, open_afternm) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_box, open_afternm)));
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
LS_API_EXEC(crypto_box, open_afternm)
{
    LS_API_F_ARGV_T(crypto_box, open_afternm) * argv;
    LS_API_READ_ARGV(crypto_box, open_afternm);

    size_t mlen = argv->clen;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_box_open_afternm(m, argv->c, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}
