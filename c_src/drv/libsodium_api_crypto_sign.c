// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_sign.h"

static void LS_API_EXEC(crypto_sign, statebytes);
static void LS_API_EXEC(crypto_sign, bytes);
static void LS_API_EXEC(crypto_sign, seedbytes);
static void LS_API_EXEC(crypto_sign, publickeybytes);
static void LS_API_EXEC(crypto_sign, secretkeybytes);
static void LS_API_EXEC(crypto_sign, messagebytes_max);
static void LS_API_EXEC(crypto_sign, primitive);
static int LS_API_INIT(crypto_sign, seed_keypair);
static void LS_API_EXEC(crypto_sign, seed_keypair);
static void LS_API_EXEC(crypto_sign, keypair);
static int LS_API_INIT(crypto_sign, crypto_sign);
static void LS_API_EXEC(crypto_sign, crypto_sign);
static int LS_API_INIT(crypto_sign, open);
static void LS_API_EXEC(crypto_sign, open);
static int LS_API_INIT(crypto_sign, detached);
static void LS_API_EXEC(crypto_sign, detached);
static int LS_API_INIT(crypto_sign, verify_detached);
static void LS_API_EXEC(crypto_sign, verify_detached);
static void LS_API_EXEC(crypto_sign, init);
static int LS_API_INIT(crypto_sign, update);
static void LS_API_EXEC(crypto_sign, update);
static int LS_API_INIT(crypto_sign, final_create);
static void LS_API_EXEC(crypto_sign, final_create);
static int LS_API_INIT(crypto_sign, final_verify);
static void LS_API_EXEC(crypto_sign, final_verify);

libsodium_function_t libsodium_functions_crypto_sign[] = {LS_API_R_ARG0(crypto_sign, statebytes),
                                                          LS_API_R_ARG0(crypto_sign, bytes),
                                                          LS_API_R_ARG0(crypto_sign, seedbytes),
                                                          LS_API_R_ARG0(crypto_sign, publickeybytes),
                                                          LS_API_R_ARG0(crypto_sign, secretkeybytes),
                                                          LS_API_R_ARG0(crypto_sign, messagebytes_max),
                                                          LS_API_R_ARG0(crypto_sign, primitive),
                                                          LS_API_R_ARGV(crypto_sign, seed_keypair, 1),
                                                          LS_API_R_ARG0(crypto_sign, keypair),
                                                          LS_API_R_ARGV(crypto_sign, crypto_sign, 2),
                                                          LS_API_R_ARGV(crypto_sign, open, 2),
                                                          LS_API_R_ARGV(crypto_sign, detached, 2),
                                                          LS_API_R_ARGV(crypto_sign, verify_detached, 3),
                                                          LS_API_R_ARG0(crypto_sign, init),
                                                          LS_API_R_ARGV(crypto_sign, update, 2),
                                                          LS_API_R_ARGV(crypto_sign, final_create, 2),
                                                          LS_API_R_ARGV(crypto_sign, final_verify, 3),
                                                          {NULL}};

/* crypto_sign_statebytes/0 */

LS_API_GET_SIZE(crypto_sign, statebytes);

/* crypto_sign_bytes/0 */

LS_API_GET_SIZE(crypto_sign, bytes);

/* crypto_sign_seedbytes/0 */

LS_API_GET_SIZE(crypto_sign, seedbytes);

/* crypto_sign_publickeybytes/0 */

LS_API_GET_SIZE(crypto_sign, publickeybytes);

/* crypto_sign_secretkeybytes/0 */

LS_API_GET_SIZE(crypto_sign, secretkeybytes);

/* crypto_sign_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_sign, messagebytes_max);

/* crypto_sign_primitive/0 */

LS_API_GET_ATOM(crypto_sign, primitive);

/* crypto_sign_seed_keypair/1 */

typedef struct LS_API_F_ARGV(crypto_sign, seed_keypair) {
    const unsigned char *seed;
} LS_API_F_ARGV_T(crypto_sign, seed_keypair);

static int
LS_API_INIT(crypto_sign, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_sign, seed_keypair) * argv;
    int type;
    int type_length;
    size_t seedbytes;
    ErlDrvSizeT x;
    void *p;

    seedbytes = crypto_sign_seedbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != seedbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(seedbytes + (sizeof(LS_API_F_ARGV_T(crypto_sign, seed_keypair))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign, seed_keypair) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign, seed_keypair)));
    argv->seed = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->seed), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_sign, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_sign, seed_keypair) * argv;
    LS_API_READ_ARGV(crypto_sign, seed_keypair);

    size_t publickeybytes = crypto_sign_publickeybytes();
    size_t secretkeybytes = crypto_sign_secretkeybytes();

    unsigned char pk[publickeybytes];
    unsigned char sk[secretkeybytes];

    LS_SAFE_REPLY(crypto_sign_seed_keypair(pk, sk, argv->seed),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(sk), secretkeybytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
    (void)sodium_memzero(sk, secretkeybytes);
}

/* crypto_sign_keypair/0 */

static void
LS_API_EXEC(crypto_sign, keypair)
{
    size_t publickeybytes = crypto_sign_publickeybytes();
    size_t secretkeybytes = crypto_sign_secretkeybytes();

    unsigned char pk[publickeybytes];
    unsigned char sk[secretkeybytes];

    LS_SAFE_REPLY(crypto_sign_keypair(pk, sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(sk), secretkeybytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(pk, publickeybytes);
    (void)sodium_memzero(sk, secretkeybytes);
}

/* crypto_sign_crypto_sign/2 */

typedef struct LS_API_F_ARGV(crypto_sign, crypto_sign) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_sign, crypto_sign);

static int
LS_API_INIT(crypto_sign, crypto_sign)
{
    LS_API_F_ARGV_T(crypto_sign, crypto_sign) * argv;
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

    secretkeybytes = crypto_sign_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign, crypto_sign))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign, crypto_sign) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign, crypto_sign)));
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
LS_API_EXEC(crypto_sign, crypto_sign)
{
    LS_API_F_ARGV_T(crypto_sign, crypto_sign) * argv;
    LS_API_READ_ARGV(crypto_sign, crypto_sign);

    size_t bytes = crypto_sign_bytes();
    unsigned char sm[bytes + argv->mlen];
    unsigned long long smlen;

    LS_SAFE_REPLY(crypto_sign(sm, &smlen, argv->m, argv->mlen, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sm), smlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(sm, bytes + argv->mlen);
}

/* crypto_sign_open/2 */

typedef struct LS_API_F_ARGV(crypto_sign, open) {
    const unsigned char *sm;
    unsigned long long smlen;
    const unsigned char *pk;
} LS_API_F_ARGV_T(crypto_sign, open);

static int
LS_API_INIT(crypto_sign, open)
{
    LS_API_F_ARGV_T(crypto_sign, open) * argv;
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

    publickeybytes = crypto_sign_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(smlen + publickeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign, open))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign, open) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign, open)));
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
LS_API_EXEC(crypto_sign, open)
{
    LS_API_F_ARGV_T(crypto_sign, open) * argv;
    LS_API_READ_ARGV(crypto_sign, open);

    size_t bytes = crypto_sign_bytes();
    size_t mbytes = (bytes > argv->smlen) ? argv->smlen : argv->smlen - bytes;
    unsigned char m[mbytes];
    unsigned long long mlen;

    LS_SAFE_REPLY(crypto_sign_open(m, &mlen, argv->sm, argv->smlen, argv->pk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mbytes);
}

/* crypto_sign_detached/2 */

typedef struct LS_API_F_ARGV(crypto_sign, detached) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *sk;
} LS_API_F_ARGV_T(crypto_sign, detached);

static int
LS_API_INIT(crypto_sign, detached)
{
    LS_API_F_ARGV_T(crypto_sign, detached) * argv;
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

    secretkeybytes = crypto_sign_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + secretkeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign, detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign, detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign, detached)));
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
LS_API_EXEC(crypto_sign, detached)
{
    LS_API_F_ARGV_T(crypto_sign, detached) * argv;
    LS_API_READ_ARGV(crypto_sign, detached);

    size_t bytes = crypto_sign_bytes();
    unsigned char sig[bytes];
    unsigned long long siglen;

    LS_SAFE_REPLY(crypto_sign_detached(sig, &siglen, argv->m, argv->mlen, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sig), siglen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(sig, bytes);
}

/* crypto_sign_verify_detached/3 */

typedef struct LS_API_F_ARGV(crypto_sign, verify_detached) {
    const unsigned char *sig;
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *pk;
} LS_API_F_ARGV_T(crypto_sign, verify_detached);

static int
LS_API_INIT(crypto_sign, verify_detached)
{
    LS_API_F_ARGV_T(crypto_sign, verify_detached) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    unsigned long long mlen;
    size_t publickeybytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_sign_bytes();

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

    publickeybytes = crypto_sign_publickeybytes();

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(bytes + mlen + publickeybytes + (sizeof(LS_API_F_ARGV_T(crypto_sign, verify_detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign, verify_detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign, verify_detached)));
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
LS_API_EXEC(crypto_sign, verify_detached)
{
    LS_API_F_ARGV_T(crypto_sign, verify_detached) * argv;
    LS_API_READ_ARGV(crypto_sign, verify_detached);

    int r = crypto_sign_verify_detached(argv->sig, argv->m, argv->mlen, argv->pk);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_init/0 */

static void
LS_API_EXEC(crypto_sign, init)
{
    size_t statebytes;
    crypto_sign_state *state;

    statebytes = crypto_sign_statebytes();

    state = (crypto_sign_state *)(sodium_malloc(statebytes));

    LS_SAFE_REPLY(
        crypto_sign_init(state),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state), statebytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_free(state);
}

/* crypto_sign_update/2 */

typedef struct LS_API_F_ARGV(crypto_sign, update) {
    crypto_sign_state *state;
    const unsigned char *m;
    unsigned long long mlen;
} LS_API_F_ARGV_T(crypto_sign, update);

static int
LS_API_INIT(crypto_sign, update)
{
    LS_API_F_ARGV_T(crypto_sign, update) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_sign_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + type_length + (sizeof(LS_API_F_ARGV_T(crypto_sign, update))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign, update) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign, update)));
    argv->state = (crypto_sign_state *)(p);
    p += statebytes;
    argv->m = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_sign, update)
{
    LS_API_F_ARGV_T(crypto_sign, update) * argv;
    LS_API_READ_ARGV(crypto_sign, update);
    size_t statebytes;

    statebytes = crypto_sign_statebytes();

    LS_SAFE_REPLY(
        crypto_sign_update(argv->state, argv->m, argv->mlen),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state), statebytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);
}

/* crypto_sign_final_create/2 */

typedef struct LS_API_F_ARGV(crypto_sign, final_create) {
    crypto_sign_state *state;
    const unsigned char sk[crypto_sign_SECRETKEYBYTES];
} LS_API_F_ARGV_T(crypto_sign, final_create);

static int
LS_API_INIT(crypto_sign, final_create)
{
    LS_API_F_ARGV_T(crypto_sign, final_create) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_sign_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_sign_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_sign, final_create))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign, final_create) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign, final_create)));
    argv->state = (crypto_sign_state *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
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
LS_API_EXEC(crypto_sign, final_create)
{
    LS_API_F_ARGV_T(crypto_sign, final_create) * argv;
    LS_API_READ_ARGV(crypto_sign, final_create);
    unsigned char sig[crypto_sign_BYTES];
    unsigned long long siglen = crypto_sign_BYTES;

    LS_SAFE_REPLY(crypto_sign_final_create(argv->state, sig, &siglen, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sig), siglen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);
}

/* crypto_sign_final_verify/3 */

typedef struct LS_API_F_ARGV(crypto_sign, final_verify) {
    crypto_sign_state *state;
    const unsigned char sig[crypto_sign_BYTES];
    const unsigned char pk[crypto_sign_PUBLICKEYBYTES];
} LS_API_F_ARGV_T(crypto_sign, final_verify);

static int
LS_API_INIT(crypto_sign, final_verify)
{
    LS_API_F_ARGV_T(crypto_sign, final_verify) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    size_t bytes;
    size_t publickeybytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_sign_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    bytes = crypto_sign_bytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != bytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_sign_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_sign, final_verify))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign, final_verify) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign, final_verify)));
    argv->state = (crypto_sign_state *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->sig), NULL) < 0) {
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
LS_API_EXEC(crypto_sign, final_verify)
{
    LS_API_F_ARGV_T(crypto_sign, final_verify) * argv;
    LS_API_READ_ARGV(crypto_sign, final_verify);

    int r = crypto_sign_final_verify(argv->state, argv->sig, argv->pk);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
