// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_sign_ed25519.h"

static void LS_API_EXEC(crypto_sign_ed25519, bytes);
static void LS_API_EXEC(crypto_sign_ed25519, seedbytes);
static void LS_API_EXEC(crypto_sign_ed25519, publickeybytes);
static void LS_API_EXEC(crypto_sign_ed25519, secretkeybytes);
static void LS_API_EXEC(crypto_sign_ed25519, messagebytes_max);
static int LS_API_INIT(crypto_sign_ed25519, crypto_sign_ed25519);
static void LS_API_EXEC(crypto_sign_ed25519, crypto_sign_ed25519);
static int LS_API_INIT(crypto_sign_ed25519, open);
static void LS_API_EXEC(crypto_sign_ed25519, open);
static int LS_API_INIT(crypto_sign_ed25519, detached);
static void LS_API_EXEC(crypto_sign_ed25519, detached);
static int LS_API_INIT(crypto_sign_ed25519, verify_detached);
static void LS_API_EXEC(crypto_sign_ed25519, verify_detached);
static void LS_API_EXEC(crypto_sign_ed25519, keypair);
static int LS_API_INIT(crypto_sign_ed25519, seed_keypair);
static void LS_API_EXEC(crypto_sign_ed25519, seed_keypair);
static int LS_API_INIT(crypto_sign_ed25519, pk_to_curve25519);
static void LS_API_EXEC(crypto_sign_ed25519, pk_to_curve25519);
static int LS_API_INIT(crypto_sign_ed25519, sk_to_curve25519);
static void LS_API_EXEC(crypto_sign_ed25519, sk_to_curve25519);
static int LS_API_INIT(crypto_sign_ed25519, sk_to_seed);
static void LS_API_EXEC(crypto_sign_ed25519, sk_to_seed);
static int LS_API_INIT(crypto_sign_ed25519, sk_to_pk);
static void LS_API_EXEC(crypto_sign_ed25519, sk_to_pk);

libsodium_function_t libsodium_functions_crypto_sign_ed25519[] = {LS_API_R_ARG0(crypto_sign_ed25519, bytes),
                                                                  LS_API_R_ARG0(crypto_sign_ed25519, seedbytes),
                                                                  LS_API_R_ARG0(crypto_sign_ed25519, publickeybytes),
                                                                  LS_API_R_ARG0(crypto_sign_ed25519, secretkeybytes),
                                                                  LS_API_R_ARG0(crypto_sign_ed25519, messagebytes_max),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, crypto_sign_ed25519, 2),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, open, 2),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, detached, 2),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, verify_detached, 3),
                                                                  LS_API_R_ARG0(crypto_sign_ed25519, keypair),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, seed_keypair, 1),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, pk_to_curve25519, 1),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, sk_to_curve25519, 1),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, sk_to_seed, 1),
                                                                  LS_API_R_ARGV(crypto_sign_ed25519, sk_to_pk, 1),
                                                                  {NULL}};

/* crypto_sign_ed25519_bytes/0 */

LS_API_GET_SIZE(crypto_sign_ed25519, bytes);

/* crypto_sign_ed25519_seedbytes/0 */

LS_API_GET_SIZE(crypto_sign_ed25519, seedbytes);

/* crypto_sign_ed25519_publickeybytes/0 */

LS_API_GET_SIZE(crypto_sign_ed25519, publickeybytes);

/* crypto_sign_ed25519_secretkeybytes/0 */

LS_API_GET_SIZE(crypto_sign_ed25519, secretkeybytes);

/* crypto_sign_ed25519_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_sign_ed25519, messagebytes_max);

/* crypto_sign_ed25519_crypto_sign_ed25519/2 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, crypto_sign_ed25519) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519);

static int
LS_API_INIT(crypto_sign_ed25519, crypto_sign_ed25519)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
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

    secretkeybytes = crypto_sign_ed25519_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519)));
    argv->m = (const unsigned char *)(p);
    p += mlen;
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
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
LS_API_EXEC(crypto_sign_ed25519, crypto_sign_ed25519)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, crypto_sign_ed25519);

    size_t bytes = crypto_sign_ed25519_bytes();
    unsigned char sm[bytes + argv->mlen];
    unsigned long long smlen;

    LS_SAFE_REPLY(crypto_sign_ed25519(sm, &smlen, argv->m, argv->mlen, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sm), smlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(sm, bytes + argv->mlen);
}

/* crypto_sign_ed25519_open/2 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, open) {
    const unsigned char *sm;
    unsigned long long smlen;
    const unsigned char *pk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, open);

static int
LS_API_INIT(crypto_sign_ed25519, open)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, open) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long smlen;
    size_t publickeybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    smlen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_sign_ed25519_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(smlen + publickeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, open))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, open) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, open)));
    argv->sm = (const unsigned char *)(p);
    p += smlen;
    argv->pk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->sm), (long *)&(argv->smlen)) < 0) {
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
LS_API_EXEC(crypto_sign_ed25519, open)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, open) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, open);

    size_t bytes = crypto_sign_ed25519_bytes();
    size_t mbytes = (bytes > argv->smlen) ? argv->smlen : argv->smlen - bytes;
    unsigned char m[mbytes];
    unsigned long long mlen;

    LS_SAFE_REPLY(crypto_sign_ed25519_open(m, &mlen, argv->sm, argv->smlen, argv->pk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mbytes);
}

/* crypto_sign_ed25519_detached/2 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, detached) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, detached);

static int
LS_API_INIT(crypto_sign_ed25519, detached)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, detached) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
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

    secretkeybytes = crypto_sign_ed25519_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, detached)));
    argv->m = (const unsigned char *)(p);
    p += mlen;
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
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
LS_API_EXEC(crypto_sign_ed25519, detached)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, detached) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, detached);

    size_t bytes = crypto_sign_ed25519_bytes();
    unsigned char sig[bytes];
    unsigned long long siglen;

    LS_SAFE_REPLY(crypto_sign_ed25519_detached(sig, &siglen, argv->m, argv->mlen, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sig), siglen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(sig, bytes);
}

/* crypto_sign_ed25519_verify_detached/3 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, verify_detached) {
    const unsigned char *sig;
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *pk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached);

static int
LS_API_INIT(crypto_sign_ed25519, verify_detached)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    unsigned long long mlen;
    size_t publickeybytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_sign_ed25519_bytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != bytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    mlen = (unsigned long long)(type_length);

    publickeybytes = crypto_sign_ed25519_publickeybytes();

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(bytes + mlen + publickeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached)));
    argv->sig = (const unsigned char *)(p);
    p += bytes;
    argv->m = (const unsigned char *)(p);
    p += mlen;
    argv->pk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->sig), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

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
LS_API_EXEC(crypto_sign_ed25519, verify_detached)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, verify_detached);

    int r = crypto_sign_ed25519_verify_detached(argv->sig, argv->m, argv->mlen, argv->pk);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_ed25519_keypair/1 */

static void
LS_API_EXEC(crypto_sign_ed25519, keypair)
{
    size_t publickeybytes = crypto_sign_ed25519_publickeybytes();
    size_t secretkeybytes = crypto_sign_ed25519_secretkeybytes();

    unsigned char pk[publickeybytes];
    unsigned char sk[secretkeybytes];

    LS_SAFE_REPLY(crypto_sign_ed25519_keypair(pk, sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(sk), secretkeybytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
    (void)sodium_memzero(sk, secretkeybytes);
}

/* crypto_sign_ed25519_seed_keypair/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, seed_keypair) {
    const unsigned char *seed;
} LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair);

static int
LS_API_INIT(crypto_sign_ed25519, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair) * argv;
    int type;
    int type_length;
    size_t seedbytes;
    ErlDrvSizeT x;
    void *p;

    seedbytes = crypto_sign_ed25519_seedbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != seedbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(seedbytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair)));
    argv->seed = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->seed), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, seed_keypair);

    size_t publickeybytes = crypto_sign_ed25519_publickeybytes();
    size_t secretkeybytes = crypto_sign_ed25519_secretkeybytes();

    unsigned char pk[publickeybytes];
    unsigned char sk[secretkeybytes];

    LS_SAFE_REPLY(crypto_sign_ed25519_seed_keypair(pk, sk, argv->seed),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(sk), secretkeybytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
    (void)sodium_memzero(sk, secretkeybytes);
}

/* crypto_sign_ed25519_pk_to_curve25519/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, pk_to_curve25519) {
    const unsigned char *ed25519_pk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519);

static int
LS_API_INIT(crypto_sign_ed25519, pk_to_curve25519)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519) * argv;
    int type;
    int type_length;
    size_t publickeybytes;
    ErlDrvSizeT x;
    void *p;

    publickeybytes = crypto_sign_ed25519_publickeybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(publickeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519)));
    argv->ed25519_pk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->ed25519_pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, pk_to_curve25519)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, pk_to_curve25519);

    size_t curve25519_bytes = crypto_scalarmult_curve25519_bytes();
    unsigned char curve25519_pk[curve25519_bytes];

    LS_SAFE_REPLY(
        crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, argv->ed25519_pk),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(curve25519_pk), curve25519_bytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(curve25519_pk, curve25519_bytes);
}

/* crypto_sign_ed25519_sk_to_curve25519/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, sk_to_curve25519) {
    const unsigned char *ed25519_sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519);

static int
LS_API_INIT(crypto_sign_ed25519, sk_to_curve25519)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519) * argv;
    int type;
    int type_length;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    secretkeybytes = crypto_sign_ed25519_secretkeybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519)));
    argv->ed25519_sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->ed25519_sk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, sk_to_curve25519)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, sk_to_curve25519);

    size_t curve25519_bytes = crypto_scalarmult_curve25519_bytes();
    unsigned char curve25519_sk[curve25519_bytes];

    LS_SAFE_REPLY(
        crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, argv->ed25519_sk),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(curve25519_sk), curve25519_bytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(curve25519_sk, curve25519_bytes);
}

/* crypto_sign_ed25519_sk_to_seed/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, sk_to_seed) {
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed);

static int
LS_API_INIT(crypto_sign_ed25519, sk_to_seed)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed) * argv;
    int type;
    int type_length;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    secretkeybytes = crypto_sign_ed25519_secretkeybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed)));
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, sk_to_seed)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, sk_to_seed);

    size_t seedbytes = crypto_sign_ed25519_seedbytes();
    unsigned char seed[seedbytes];

    LS_SAFE_REPLY(crypto_sign_ed25519_sk_to_seed(seed, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(seed), seedbytes, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(seed, seedbytes);
}

/* crypto_sign_ed25519_sk_to_pk/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, sk_to_pk) {
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk);

static int
LS_API_INIT(crypto_sign_ed25519, sk_to_pk)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk) * argv;
    int type;
    int type_length;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    secretkeybytes = crypto_sign_ed25519_secretkeybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk)));
    argv->sk = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, sk_to_pk)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519, sk_to_pk);

    size_t publickeybytes = crypto_sign_ed25519_publickeybytes();
    unsigned char pk[publickeybytes];

    LS_SAFE_REPLY(crypto_sign_ed25519_sk_to_pk(pk, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
}
