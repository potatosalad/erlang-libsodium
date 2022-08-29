// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_hash_sha256.h"

static void LS_API_EXEC(crypto_hash_sha256, statebytes);
static void LS_API_EXEC(crypto_hash_sha256, bytes);
static int LS_API_INIT(crypto_hash_sha256, crypto_hash_sha256);
static void LS_API_EXEC(crypto_hash_sha256, crypto_hash_sha256);
static void LS_API_EXEC(crypto_hash_sha256, init);
static int LS_API_INIT(crypto_hash_sha256, update);
static void LS_API_EXEC(crypto_hash_sha256, update);
static int LS_API_INIT(crypto_hash_sha256, final);
static void LS_API_EXEC(crypto_hash_sha256, final);

libsodium_function_t libsodium_functions_crypto_hash_sha256[] = {LS_API_R_ARG0(crypto_hash_sha256, statebytes),
                                                                 LS_API_R_ARG0(crypto_hash_sha256, bytes),
                                                                 LS_API_R_ARGV(crypto_hash_sha256, crypto_hash_sha256, 1),
                                                                 LS_API_R_ARG0(crypto_hash_sha256, init),
                                                                 LS_API_R_ARGV(crypto_hash_sha256, update, 2),
                                                                 LS_API_R_ARGV(crypto_hash_sha256, final, 1),
                                                                 {NULL}};

/* crypto_hash_sha256_statebytes/0 */

static void
LS_API_EXEC(crypto_hash_sha256, statebytes)
{
    size_t statebytes;

    statebytes = crypto_hash_sha256_statebytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(statebytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_hash_sha256_bytes/0 */

static void
LS_API_EXEC(crypto_hash_sha256, bytes)
{
    size_t bytes;

    bytes = crypto_hash_sha256_bytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_hash_sha256_crypto_hash_sha256/1 */

typedef struct LS_API_F_ARGV(crypto_hash_sha256, crypto_hash_sha256) {
    const unsigned char *in;
    unsigned long long inlen;
} LS_API_F_ARGV_T(crypto_hash_sha256, crypto_hash_sha256);

static int
LS_API_INIT(crypto_hash_sha256, crypto_hash_sha256)
{
    LS_API_F_ARGV_T(crypto_hash_sha256, crypto_hash_sha256) * argv;
    int type;
    int type_length;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    x = (ErlDrvSizeT)(type_length + (sizeof(LS_API_F_ARGV_T(crypto_hash_sha256, crypto_hash_sha256))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_hash_sha256, crypto_hash_sha256) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_hash_sha256, crypto_hash_sha256)));
    argv->in = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->inlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_hash_sha256, crypto_hash_sha256)
{
    LS_API_F_ARGV_T(crypto_hash_sha256, crypto_hash_sha256) * argv;
    LS_API_READ_ARGV(crypto_hash_sha256, crypto_hash_sha256);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_hash_sha256_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_hash_sha256(out, argv->in, argv->inlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(out);
}

/* crypto_hash_sha256_init/0 */

static void
LS_API_EXEC(crypto_hash_sha256, init)
{
    size_t statebytes;
    crypto_hash_sha256_state *state;

    statebytes = crypto_hash_sha256_statebytes();

    state = (crypto_hash_sha256_state *)(sodium_malloc(statebytes));

    if (state == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_hash_sha256_init(state);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_free(state);
}

/* crypto_hash_sha256_update/2 */

typedef struct LS_API_F_ARGV(crypto_hash_sha256, update) {
    crypto_hash_sha256_state *state;
    const unsigned char *in;
    unsigned long long inlen;
} LS_API_F_ARGV_T(crypto_hash_sha256, update);

static int
LS_API_INIT(crypto_hash_sha256, update)
{
    LS_API_F_ARGV_T(crypto_hash_sha256, update) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_hash_sha256_statebytes();

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

    x = (ErlDrvSizeT)(statebytes + type_length + (sizeof(LS_API_F_ARGV_T(crypto_hash_sha256, update))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_hash_sha256, update) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_hash_sha256, update)));
    argv->state = (crypto_hash_sha256_state *)(p);
    p += statebytes;
    argv->in = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->inlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_hash_sha256, update)
{
    LS_API_F_ARGV_T(crypto_hash_sha256, update) * argv;
    LS_API_READ_ARGV(crypto_hash_sha256, update);
    size_t statebytes;

    statebytes = crypto_hash_sha256_statebytes();

    (void)crypto_hash_sha256_update(argv->state, argv->in, argv->inlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_hash_sha256_final/1 */

typedef struct LS_API_F_ARGV(crypto_hash_sha256, final) {
    crypto_hash_sha256_state *state;
} LS_API_F_ARGV_T(crypto_hash_sha256, final);

static int
LS_API_INIT(crypto_hash_sha256, final)
{
    LS_API_F_ARGV_T(crypto_hash_sha256, final) * argv;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_hash_sha256_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_hash_sha256, final))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_hash_sha256, final) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_hash_sha256, final)));
    argv->state = (crypto_hash_sha256_state *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_hash_sha256, final)
{
    LS_API_F_ARGV_T(crypto_hash_sha256, final) * argv;
    LS_API_READ_ARGV(crypto_hash_sha256, final);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_hash_sha256_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_hash_sha256_final(argv->state, out);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
