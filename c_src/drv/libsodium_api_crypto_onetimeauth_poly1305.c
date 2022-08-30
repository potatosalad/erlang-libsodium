// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_onetimeauth_poly1305.h"

static void LS_API_EXEC(crypto_onetimeauth_poly1305, bytes);
static void LS_API_EXEC(crypto_onetimeauth_poly1305, keybytes);
static int LS_API_INIT(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305);
static void LS_API_EXEC(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305);
static int LS_API_INIT(crypto_onetimeauth_poly1305, verify);
static void LS_API_EXEC(crypto_onetimeauth_poly1305, verify);
static int LS_API_INIT(crypto_onetimeauth_poly1305, init);
static void LS_API_EXEC(crypto_onetimeauth_poly1305, init);
static int LS_API_INIT(crypto_onetimeauth_poly1305, update);
static void LS_API_EXEC(crypto_onetimeauth_poly1305, update);
static int LS_API_INIT(crypto_onetimeauth_poly1305, final);
static void LS_API_EXEC(crypto_onetimeauth_poly1305, final);
static void LS_API_EXEC(crypto_onetimeauth_poly1305, keygen);

libsodium_function_t libsodium_functions_crypto_onetimeauth_poly1305[] = {
    LS_API_R_ARG0(crypto_onetimeauth_poly1305, bytes),
    LS_API_R_ARG0(crypto_onetimeauth_poly1305, keybytes),
    LS_API_R_ARGV(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305, 2),
    LS_API_R_ARGV(crypto_onetimeauth_poly1305, verify, 3),
    LS_API_R_ARGV(crypto_onetimeauth_poly1305, init, 1),
    LS_API_R_ARGV(crypto_onetimeauth_poly1305, update, 2),
    LS_API_R_ARGV(crypto_onetimeauth_poly1305, final, 1),
    LS_API_R_ARG0(crypto_onetimeauth_poly1305, keygen),
    {NULL}};

#define LS_API_CRYPTO_ONETIMEAUTH_POLY1305_STATEBYTES (sizeof(crypto_onetimeauth_poly1305_state))

/* crypto_onetimeauth_poly1305_bytes/0 */

static void
LS_API_EXEC(crypto_onetimeauth_poly1305, bytes)
{
    size_t bytes;

    bytes = crypto_onetimeauth_poly1305_bytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_poly1305_keybytes/0 */

static void
LS_API_EXEC(crypto_onetimeauth_poly1305, keybytes)
{
    size_t keybytes;

    keybytes = crypto_onetimeauth_poly1305_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_poly1305_crypto_onetimeauth_poly1305/2 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305) {
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305);

static int
LS_API_INIT(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305) * argv;
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

    keybytes = crypto_onetimeauth_poly1305_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305)));
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
LS_API_EXEC(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth_poly1305, crypto_onetimeauth_poly1305);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_onetimeauth_poly1305_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_onetimeauth_poly1305(out, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(out);
}

/* crypto_onetimeauth_poly1305_verify/3 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth_poly1305, verify) {
    const unsigned char *h;
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, verify);

static int
LS_API_INIT(crypto_onetimeauth_poly1305, verify)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, verify) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    size_t inlen;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_onetimeauth_poly1305_bytes();
    keybytes = crypto_onetimeauth_poly1305_keybytes();

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

    x = (ErlDrvSizeT)(bytes + inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, verify))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, verify) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, verify)));
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
LS_API_EXEC(crypto_onetimeauth_poly1305, verify)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, verify) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth_poly1305, verify);
    int r;

    r = crypto_onetimeauth_poly1305_verify(argv->h, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_poly1305_init/1 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth_poly1305, init) {
    const unsigned char *key;
} LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, init);

static int
LS_API_INIT(crypto_onetimeauth_poly1305, init)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, init) * argv;
    int type;
    int type_length;
    size_t keylen;
    ErlDrvSizeT x;
    void *p;

    keylen = crypto_onetimeauth_poly1305_keybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keylen) {
        return -1;
    }

    x = (ErlDrvSizeT)(keylen + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, init))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, init) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, init)));
    argv->key = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->key), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_onetimeauth_poly1305, init)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, init) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth_poly1305, init);
    size_t statebytes;
    crypto_onetimeauth_poly1305_state *state;

    statebytes = LS_API_CRYPTO_ONETIMEAUTH_POLY1305_STATEBYTES;

    state = (crypto_onetimeauth_poly1305_state *)(sodium_malloc(statebytes));

    if (state == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_onetimeauth_poly1305_init(state, argv->key);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_free(state);
}

/* crypto_onetimeauth_poly1305_update/2 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth_poly1305, update) {
    crypto_onetimeauth_poly1305_state *state;
    const unsigned char *in;
    unsigned long long inlen;
} LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, update);

static int
LS_API_INIT(crypto_onetimeauth_poly1305, update)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, update) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = LS_API_CRYPTO_ONETIMEAUTH_POLY1305_STATEBYTES;

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

    x = (ErlDrvSizeT)(statebytes + type_length + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, update))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, update) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, update)));
    argv->state = (crypto_onetimeauth_poly1305_state *)(p);
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
LS_API_EXEC(crypto_onetimeauth_poly1305, update)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, update) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth_poly1305, update);
    size_t statebytes;

    statebytes = LS_API_CRYPTO_ONETIMEAUTH_POLY1305_STATEBYTES;

    (void)crypto_onetimeauth_poly1305_update(argv->state, argv->in, argv->inlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_poly1305_final/1 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth_poly1305, final) {
    crypto_onetimeauth_poly1305_state *state;
} LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, final);

static int
LS_API_INIT(crypto_onetimeauth_poly1305, final)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, final) * argv;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = LS_API_CRYPTO_ONETIMEAUTH_POLY1305_STATEBYTES;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, final))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, final) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, final)));
    argv->state = (crypto_onetimeauth_poly1305_state *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_onetimeauth_poly1305, final)
{
    LS_API_F_ARGV_T(crypto_onetimeauth_poly1305, final) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth_poly1305, final);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_onetimeauth_poly1305_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_onetimeauth_poly1305_final(argv->state, out);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_keygen/0 */

static void
LS_API_EXEC(crypto_onetimeauth_poly1305, keygen)
{
    unsigned char k[crypto_onetimeauth_poly1305_KEYBYTES];

    (void)crypto_onetimeauth_poly1305_keygen(k);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k), crypto_onetimeauth_poly1305_KEYBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
