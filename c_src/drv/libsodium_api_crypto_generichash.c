// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_generichash.h"

static void LS_API_EXEC(crypto_generichash, bytes_min);
static void LS_API_EXEC(crypto_generichash, bytes_max);
static void LS_API_EXEC(crypto_generichash, bytes);
static void LS_API_EXEC(crypto_generichash, keybytes_min);
static void LS_API_EXEC(crypto_generichash, keybytes_max);
static void LS_API_EXEC(crypto_generichash, keybytes);
static void LS_API_EXEC(crypto_generichash, primitive);
static void LS_API_EXEC(crypto_generichash, statebytes);
static int LS_API_INIT(crypto_generichash, crypto_generichash);
static void LS_API_EXEC(crypto_generichash, crypto_generichash);
static int LS_API_INIT(crypto_generichash, init);
static void LS_API_EXEC(crypto_generichash, init);
static int LS_API_INIT(crypto_generichash, update);
static void LS_API_EXEC(crypto_generichash, update);
static int LS_API_INIT(crypto_generichash, final);
static void LS_API_EXEC(crypto_generichash, final);
static void LS_API_EXEC(crypto_generichash, keygen);

libsodium_function_t libsodium_functions_crypto_generichash[] = {LS_API_R_ARG0(crypto_generichash, bytes_min),
                                                                 LS_API_R_ARG0(crypto_generichash, bytes_max),
                                                                 LS_API_R_ARG0(crypto_generichash, bytes),
                                                                 LS_API_R_ARG0(crypto_generichash, keybytes_min),
                                                                 LS_API_R_ARG0(crypto_generichash, keybytes_max),
                                                                 LS_API_R_ARG0(crypto_generichash, keybytes),
                                                                 LS_API_R_ARG0(crypto_generichash, primitive),
                                                                 LS_API_R_ARG0(crypto_generichash, statebytes),
                                                                 LS_API_R_ARGV(crypto_generichash, crypto_generichash, 3),
                                                                 LS_API_R_ARGV(crypto_generichash, init, 2),
                                                                 LS_API_R_ARGV(crypto_generichash, update, 2),
                                                                 LS_API_R_ARGV(crypto_generichash, final, 2),
                                                                 LS_API_R_ARG0(crypto_generichash, keygen),
                                                                 {NULL}};

/* crypto_generichash_bytes_min/0 */

static void
LS_API_EXEC(crypto_generichash, bytes_min)
{
    size_t bytes_min;

    bytes_min = crypto_generichash_bytes_min();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes_min), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_generichash_bytes_max/0 */

static void
LS_API_EXEC(crypto_generichash, bytes_max)
{
    size_t bytes_max;

    bytes_max = crypto_generichash_bytes_max();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes_max), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_generichash_bytes/0 */

static void
LS_API_EXEC(crypto_generichash, bytes)
{
    size_t bytes;

    bytes = crypto_generichash_bytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_generichash_keybytes_min/0 */

static void
LS_API_EXEC(crypto_generichash, keybytes_min)
{
    size_t keybytes_min;

    keybytes_min = crypto_generichash_keybytes_min();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes_min), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_generichash_keybytes_max/0 */

static void
LS_API_EXEC(crypto_generichash, keybytes_max)
{
    size_t keybytes_max;

    keybytes_max = crypto_generichash_keybytes_max();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes_max), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_generichash_keybytes/0 */

static void
LS_API_EXEC(crypto_generichash, keybytes)
{
    size_t keybytes;

    keybytes = crypto_generichash_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_generichash_primitive/0 */

static void
LS_API_EXEC(crypto_generichash, primitive)
{
    const char *primitive;

    primitive = crypto_generichash_primitive();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_ATOM, driver_mk_atom((char *)(primitive)), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_generichash_statebytes/0 */

static void
LS_API_EXEC(crypto_generichash, statebytes)
{
    size_t statebytes;

    statebytes = crypto_generichash_statebytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(statebytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_generichash_crypto_generichash/3 */

typedef struct LS_API_F_ARGV(crypto_generichash, crypto_generichash) {
    size_t outlen;
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *key;
    size_t keylen;
} LS_API_F_ARGV_T(crypto_generichash, crypto_generichash);

static int
LS_API_INIT(crypto_generichash, crypto_generichash)
{
    LS_API_F_ARGV_T(crypto_generichash, crypto_generichash) * argv;
    int skip;
    int type;
    int type_length;
    size_t outlen;
    unsigned long long inlen;
    size_t keylen;
    ErlDrvSizeT x;
    void *p;

    if (ei_decode_ulong(buffer, index, (unsigned long *)&(outlen)) < 0) {
        return -1;
    }

    if (outlen > crypto_generichash_bytes_max() || outlen < crypto_generichash_bytes_min()) {
        return -1;
    }

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    inlen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    keylen = (size_t)(type_length);

    if (keylen != 0 && (keylen > crypto_generichash_keybytes_max() || keylen < crypto_generichash_keybytes_min())) {
        return -1;
    }

    x = (ErlDrvSizeT)(inlen + keylen + (sizeof(LS_API_F_ARGV_T(crypto_generichash, crypto_generichash))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_generichash, crypto_generichash) *)(p);
    argv->outlen = outlen;
    p += (sizeof(LS_API_F_ARGV_T(crypto_generichash, crypto_generichash)));
    argv->in = (const unsigned char *)(p);

    if (keylen == 0) {
        argv->key = NULL;
        argv->keylen = 0;
    } else {
        p += inlen;
        argv->key = (const unsigned char *)(p);
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->inlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (keylen > 0) {
        if (ei_decode_binary(buffer, index, (void *)(argv->key), (long *)&(argv->keylen)) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_generichash, crypto_generichash)
{
    LS_API_F_ARGV_T(crypto_generichash, crypto_generichash) * argv;
    LS_API_READ_ARGV(crypto_generichash, crypto_generichash);
    unsigned char *out;

    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->outlen)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(crypto_generichash(out, argv->outlen, argv->in, argv->inlen, argv->key, argv->keylen),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->outlen, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)driver_free(out);
}

/* crypto_generichash_init/2 */

typedef struct LS_API_F_ARGV(crypto_generichash, init) {
    const unsigned char *key;
    size_t keylen;
    size_t outlen;
} LS_API_F_ARGV_T(crypto_generichash, init);

static int
LS_API_INIT(crypto_generichash, init)
{
    LS_API_F_ARGV_T(crypto_generichash, init) * argv;
    int skip;
    int type;
    int type_length;
    size_t keylen;
    size_t outlen;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    keylen = (size_t)(type_length);

    if (keylen != 0 && (keylen > crypto_generichash_keybytes_max() || keylen < crypto_generichash_keybytes_min())) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(outlen)) < 0) {
        return -1;
    }

    if (outlen > crypto_generichash_bytes_max() || outlen < crypto_generichash_bytes_min()) {
        return -1;
    }

    x = (ErlDrvSizeT)(keylen + (sizeof(LS_API_F_ARGV_T(crypto_generichash, init))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_generichash, init) *)(p);

    if (keylen == 0) {
        argv->key = NULL;
        argv->keylen = 0;
    } else {
        p += (sizeof(LS_API_F_ARGV_T(crypto_generichash, init)));
        argv->key = (const unsigned char *)(p);
        if (ei_decode_binary(buffer, index, (void *)(argv->key), (long *)&(argv->keylen)) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    argv->outlen = outlen;

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_generichash, init)
{
    LS_API_F_ARGV_T(crypto_generichash, init) * argv;
    LS_API_READ_ARGV(crypto_generichash, init);
    size_t statebytes;
    crypto_generichash_state *state;

    statebytes = crypto_generichash_statebytes();

    state = (crypto_generichash_state *)(sodium_malloc(statebytes));

    if (state == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(
        crypto_generichash_init(state, argv->key, argv->keylen, argv->outlen),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state), statebytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_free(state);
}

/* crypto_generichash_update/2 */

typedef struct LS_API_F_ARGV(crypto_generichash, update) {
    crypto_generichash_state *state;
    const unsigned char *in;
    unsigned long long inlen;
} LS_API_F_ARGV_T(crypto_generichash, update);

static int
LS_API_INIT(crypto_generichash, update)
{
    LS_API_F_ARGV_T(crypto_generichash, update) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_generichash_statebytes();

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

    x = (ErlDrvSizeT)(statebytes + type_length + (sizeof(LS_API_F_ARGV_T(crypto_generichash, update))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_generichash, update) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_generichash, update)));
    argv->state = (crypto_generichash_state *)(p);
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
LS_API_EXEC(crypto_generichash, update)
{
    LS_API_F_ARGV_T(crypto_generichash, update) * argv;
    LS_API_READ_ARGV(crypto_generichash, update);
    size_t statebytes;

    statebytes = crypto_generichash_statebytes();

    LS_SAFE_REPLY(
        crypto_generichash_update(argv->state, argv->in, argv->inlen),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state), statebytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);
}

/* crypto_generichash_final/2 */

typedef struct LS_API_F_ARGV(crypto_generichash, final) {
    crypto_generichash_state *state;
    size_t outlen;
} LS_API_F_ARGV_T(crypto_generichash, final);

static int
LS_API_INIT(crypto_generichash, final)
{
    LS_API_F_ARGV_T(crypto_generichash, final) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    size_t outlen;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_generichash_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(outlen)) < 0) {
        return -1;
    }

    if (outlen > crypto_generichash_bytes_max() || outlen < crypto_generichash_bytes_min()) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_generichash, final))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_generichash, final) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_generichash, final)));
    argv->state = (crypto_generichash_state *)(p);
    argv->outlen = outlen;

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_generichash, final)
{
    LS_API_F_ARGV_T(crypto_generichash, final) * argv;
    LS_API_READ_ARGV(crypto_generichash, final);
    unsigned char *out;

    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->outlen)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(crypto_generichash_final(argv->state, out, argv->outlen),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->outlen, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)driver_free(out);
}

/* crypto_generichash_keygen/0 */

static void
LS_API_EXEC(crypto_generichash, keygen)
{
    unsigned char k[crypto_generichash_KEYBYTES];

    (void)crypto_generichash_keygen(k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request),         ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k),
                             crypto_generichash_KEYBYTES, ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
