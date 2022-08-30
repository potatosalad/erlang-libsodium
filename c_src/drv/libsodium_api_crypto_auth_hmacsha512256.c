// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_auth_hmacsha512256.h"

static void LS_API_EXEC(crypto_auth_hmacsha512256, bytes);
static void LS_API_EXEC(crypto_auth_hmacsha512256, keybytes);
static int LS_API_INIT(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256);
static void LS_API_EXEC(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256);
static int LS_API_INIT(crypto_auth_hmacsha512256, verify);
static void LS_API_EXEC(crypto_auth_hmacsha512256, verify);
static void LS_API_EXEC(crypto_auth_hmacsha512256, statebytes);
static int LS_API_INIT(crypto_auth_hmacsha512256, init);
static void LS_API_EXEC(crypto_auth_hmacsha512256, init);
static int LS_API_INIT(crypto_auth_hmacsha512256, update);
static void LS_API_EXEC(crypto_auth_hmacsha512256, update);
static int LS_API_INIT(crypto_auth_hmacsha512256, final);
static void LS_API_EXEC(crypto_auth_hmacsha512256, final);
static void LS_API_EXEC(crypto_auth_hmacsha512256, keygen);

libsodium_function_t libsodium_functions_crypto_auth_hmacsha512256[] = {
    LS_API_R_ARG0(crypto_auth_hmacsha512256, bytes),
    LS_API_R_ARG0(crypto_auth_hmacsha512256, keybytes),
    LS_API_R_ARGV(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256, 2),
    LS_API_R_ARGV(crypto_auth_hmacsha512256, verify, 3),
    LS_API_R_ARG0(crypto_auth_hmacsha512256, statebytes),
    LS_API_R_ARGV(crypto_auth_hmacsha512256, init, 1),
    LS_API_R_ARGV(crypto_auth_hmacsha512256, update, 2),
    LS_API_R_ARGV(crypto_auth_hmacsha512256, final, 1),
    LS_API_R_ARG0(crypto_auth_hmacsha512256, keygen),
    {NULL}};

/* crypto_auth_hmacsha512256_bytes/0 */

static void
LS_API_EXEC(crypto_auth_hmacsha512256, bytes)
{
    size_t bytes;

    bytes = crypto_auth_hmacsha512256_bytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_hmacsha512256_keybytes/0 */

static void
LS_API_EXEC(crypto_auth_hmacsha512256, keybytes)
{
    size_t keybytes;

    keybytes = crypto_auth_hmacsha512256_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_hmacsha512256_crypto_auth_hmacsha512256/2 */

typedef struct LS_API_F_ARGV(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256) {
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256);

static int
LS_API_INIT(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long inlen;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    inlen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_auth_hmacsha512256_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256)));
    argv->in = (const unsigned char *)(p);
    p += inlen;
    argv->k = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->inlen)) < 0) {
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
LS_API_EXEC(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256) * argv;
    LS_API_READ_ARGV(crypto_auth_hmacsha512256, crypto_auth_hmacsha512256);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_auth_hmacsha512256_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_auth_hmacsha512256(out, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(out);
}

/* crypto_auth_hmacsha512256_verify/3 */

typedef struct LS_API_F_ARGV(crypto_auth_hmacsha512256, verify) {
    const unsigned char *h;
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_auth_hmacsha512256, verify);

static int
LS_API_INIT(crypto_auth_hmacsha512256, verify)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, verify) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    size_t inlen;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_auth_hmacsha512256_bytes();
    keybytes = crypto_auth_hmacsha512256_keybytes();

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

    inlen = (size_t)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(bytes + inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, verify))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_auth_hmacsha512256, verify) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, verify)));
    argv->h = (const unsigned char *)(p);
    p += bytes;
    argv->in = (const unsigned char *)(p);
    p += inlen;
    argv->k = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->h), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->inlen)) < 0) {
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
LS_API_EXEC(crypto_auth_hmacsha512256, verify)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, verify) * argv;
    LS_API_READ_ARGV(crypto_auth_hmacsha512256, verify);
    int r;

    r = crypto_auth_hmacsha512256_verify(argv->h, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_hmacsha512256_statebytes/0 */

static void
LS_API_EXEC(crypto_auth_hmacsha512256, statebytes)
{
    size_t statebytes;

    statebytes = crypto_auth_hmacsha512256_statebytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(statebytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_hmacsha512256_init/1 */

typedef struct LS_API_F_ARGV(crypto_auth_hmacsha512256, init) {
    const unsigned char *key;
} LS_API_F_ARGV_T(crypto_auth_hmacsha512256, init);

static int
LS_API_INIT(crypto_auth_hmacsha512256, init)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, init) * argv;
    int type;
    int type_length;
    size_t keylen;
    ErlDrvSizeT x;
    void *p;

    keylen = crypto_auth_hmacsha512256_keybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keylen) {
        return -1;
    }

    x = (ErlDrvSizeT)(keylen + (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, init))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_auth_hmacsha512256, init) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, init)));
    argv->key = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->key), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_auth_hmacsha512256, init)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, init) * argv;
    LS_API_READ_ARGV(crypto_auth_hmacsha512256, init);
    size_t statebytes;
    crypto_auth_hmacsha512256_state *state;

    statebytes = crypto_auth_hmacsha512256_statebytes();

    state = (crypto_auth_hmacsha512256_state *)(sodium_malloc(statebytes));

    if (state == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_auth_hmacsha512256_init(state, argv->key, crypto_auth_hmacsha512256_keybytes());

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_free(state);
}

/* crypto_auth_hmacsha512256_update/2 */

typedef struct LS_API_F_ARGV(crypto_auth_hmacsha512256, update) {
    crypto_auth_hmacsha512256_state *state;
    const unsigned char *in;
    unsigned long long inlen;
} LS_API_F_ARGV_T(crypto_auth_hmacsha512256, update);

static int
LS_API_INIT(crypto_auth_hmacsha512256, update)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, update) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_auth_hmacsha512256_statebytes();

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

    x = (ErlDrvSizeT)(statebytes + type_length + (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, update))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_auth_hmacsha512256, update) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, update)));
    argv->state = (crypto_auth_hmacsha512256_state *)(p);
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
LS_API_EXEC(crypto_auth_hmacsha512256, update)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, update) * argv;
    LS_API_READ_ARGV(crypto_auth_hmacsha512256, update);
    size_t statebytes;

    statebytes = crypto_auth_hmacsha512256_statebytes();

    (void)crypto_auth_hmacsha512256_update(argv->state, argv->in, argv->inlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_hmacsha512256_final/1 */

typedef struct LS_API_F_ARGV(crypto_auth_hmacsha512256, final) {
    crypto_auth_hmacsha512256_state *state;
} LS_API_F_ARGV_T(crypto_auth_hmacsha512256, final);

static int
LS_API_INIT(crypto_auth_hmacsha512256, final)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, final) * argv;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_auth_hmacsha512256_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, final))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_auth_hmacsha512256, final) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_auth_hmacsha512256, final)));
    argv->state = (crypto_auth_hmacsha512256_state *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_auth_hmacsha512256, final)
{
    LS_API_F_ARGV_T(crypto_auth_hmacsha512256, final) * argv;
    LS_API_READ_ARGV(crypto_auth_hmacsha512256, final);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_auth_hmacsha512256_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_auth_hmacsha512256_final(argv->state, out);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_hmacsha512256_keygen/0 */

static void
LS_API_EXEC(crypto_auth_hmacsha512256, keygen)
{
    unsigned char k[crypto_auth_hmacsha512256_KEYBYTES];

    (void)crypto_auth_hmacsha512256_keygen(k);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k), crypto_auth_hmacsha512256_KEYBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
