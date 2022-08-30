// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_sign_ed25519ph.h"

static void LS_API_EXEC(crypto_sign_ed25519ph, statebytes);
static void LS_API_EXEC(crypto_sign_ed25519ph, init);
static int LS_API_INIT(crypto_sign_ed25519ph, update);
static void LS_API_EXEC(crypto_sign_ed25519ph, update);
static int LS_API_INIT(crypto_sign_ed25519ph, final_create);
static void LS_API_EXEC(crypto_sign_ed25519ph, final_create);
static int LS_API_INIT(crypto_sign_ed25519ph, final_verify);
static void LS_API_EXEC(crypto_sign_ed25519ph, final_verify);

libsodium_function_t libsodium_functions_crypto_sign_ed25519ph[] = {
    LS_API_R_ARG0(crypto_sign_ed25519ph, statebytes),      LS_API_R_ARG0(crypto_sign_ed25519ph, init),
    LS_API_R_ARGV(crypto_sign_ed25519ph, update, 2),       LS_API_R_ARGV(crypto_sign_ed25519ph, final_create, 2),
    LS_API_R_ARGV(crypto_sign_ed25519ph, final_verify, 3), {NULL}};

/* crypto_sign_ed25519ph_statebytes/0 */

LS_API_GET_SIZE(crypto_sign_ed25519ph, statebytes);

/* crypto_sign_ed25519ph_init/0 */

static void
LS_API_EXEC(crypto_sign_ed25519ph, init)
{
    size_t statebytes;
    crypto_sign_ed25519ph_state *state;

    statebytes = crypto_sign_ed25519ph_statebytes();

    state = (crypto_sign_ed25519ph_state *)(sodium_malloc(statebytes));

    LS_SAFE_REPLY(
        crypto_sign_ed25519ph_init(state),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state), statebytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_free(state);
}

/* crypto_sign_ed25519ph_update/2 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519ph, update) {
    crypto_sign_ed25519ph_state *state;
    const unsigned char *m;
    unsigned long long mlen;
} LS_API_F_ARGV_T(crypto_sign_ed25519ph, update);

static int
LS_API_INIT(crypto_sign_ed25519ph, update)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519ph, update) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_sign_ed25519ph_statebytes();

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

    x = (ErlDrvSizeT)(statebytes + type_length + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519ph, update))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519ph, update) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519ph, update)));
    argv->state = (crypto_sign_ed25519ph_state *)(p);
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
LS_API_EXEC(crypto_sign_ed25519ph, update)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519ph, update) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519ph, update);
    size_t statebytes;

    statebytes = crypto_sign_ed25519ph_statebytes();

    LS_SAFE_REPLY(
        crypto_sign_ed25519ph_update(argv->state, argv->m, argv->mlen),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state), statebytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);
}

/* crypto_sign_ed25519ph_final_create/2 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519ph, final_create) {
    crypto_sign_ed25519ph_state *state;
    const unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
} LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_create);

static int
LS_API_INIT(crypto_sign_ed25519ph, final_create)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_create) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_sign_ed25519ph_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_sign_ed25519_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_create))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_create) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_create)));
    argv->state = (crypto_sign_ed25519ph_state *)(p);

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
LS_API_EXEC(crypto_sign_ed25519ph, final_create)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_create) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519ph, final_create);
    unsigned char sig[crypto_sign_ed25519_BYTES];
    unsigned long long siglen = crypto_sign_ed25519_BYTES;

    LS_SAFE_REPLY(crypto_sign_ed25519ph_final_create(argv->state, sig, &siglen, argv->sk),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sig), siglen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);
}

/* crypto_sign_ed25519ph_final_verify/3 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519ph, final_verify) {
    crypto_sign_ed25519ph_state *state;
    const unsigned char sig[crypto_sign_ed25519_BYTES];
    const unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
} LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_verify);

static int
LS_API_INIT(crypto_sign_ed25519ph, final_verify)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_verify) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    size_t bytes;
    size_t publickeybytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_sign_ed25519ph_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    bytes = crypto_sign_ed25519_bytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != bytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    publickeybytes = crypto_sign_ed25519_publickeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_verify))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_verify) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_verify)));
    argv->state = (crypto_sign_ed25519ph_state *)(p);

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
LS_API_EXEC(crypto_sign_ed25519ph, final_verify)
{
    LS_API_F_ARGV_T(crypto_sign_ed25519ph, final_verify) * argv;
    LS_API_READ_ARGV(crypto_sign_ed25519ph, final_verify);

    int r = crypto_sign_ed25519ph_final_verify(argv->state, argv->sig, argv->pk);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
