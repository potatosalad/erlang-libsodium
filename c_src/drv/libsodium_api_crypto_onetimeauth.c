// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_onetimeauth.h"

static void LS_API_EXEC(crypto_onetimeauth, statebytes);
static void LS_API_EXEC(crypto_onetimeauth, bytes);
static void LS_API_EXEC(crypto_onetimeauth, keybytes);
static void LS_API_EXEC(crypto_onetimeauth, primitive);
static int LS_API_INIT(crypto_onetimeauth, crypto_onetimeauth);
static void LS_API_EXEC(crypto_onetimeauth, crypto_onetimeauth);
static int LS_API_INIT(crypto_onetimeauth, verify);
static void LS_API_EXEC(crypto_onetimeauth, verify);
static int LS_API_INIT(crypto_onetimeauth, init);
static void LS_API_EXEC(crypto_onetimeauth, init);
static int LS_API_INIT(crypto_onetimeauth, update);
static void LS_API_EXEC(crypto_onetimeauth, update);
static int LS_API_INIT(crypto_onetimeauth, final);
static void LS_API_EXEC(crypto_onetimeauth, final);
static void LS_API_EXEC(crypto_onetimeauth, keygen);

libsodium_function_t libsodium_functions_crypto_onetimeauth[] = {LS_API_R_ARG0(crypto_onetimeauth, statebytes),
                                                                 LS_API_R_ARG0(crypto_onetimeauth, bytes),
                                                                 LS_API_R_ARG0(crypto_onetimeauth, keybytes),
                                                                 LS_API_R_ARG0(crypto_onetimeauth, primitive),
                                                                 LS_API_R_ARGV(crypto_onetimeauth, crypto_onetimeauth, 2),
                                                                 LS_API_R_ARGV(crypto_onetimeauth, verify, 3),
                                                                 LS_API_R_ARGV(crypto_onetimeauth, init, 1),
                                                                 LS_API_R_ARGV(crypto_onetimeauth, update, 2),
                                                                 LS_API_R_ARGV(crypto_onetimeauth, final, 1),
                                                                 LS_API_R_ARG0(crypto_onetimeauth, keygen),
                                                                 {NULL}};

/* crypto_onetimeauth_statebytes/0 */

static void
LS_API_EXEC(crypto_onetimeauth, statebytes)
{
    size_t statebytes;

    statebytes = crypto_onetimeauth_statebytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(statebytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_bytes/0 */

static void
LS_API_EXEC(crypto_onetimeauth, bytes)
{
    size_t bytes;

    bytes = crypto_onetimeauth_bytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_keybytes/0 */

static void
LS_API_EXEC(crypto_onetimeauth, keybytes)
{
    size_t keybytes;

    keybytes = crypto_onetimeauth_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_primitive/0 */

static void
LS_API_EXEC(crypto_onetimeauth, primitive)
{
    const char *primitive;

    primitive = crypto_onetimeauth_primitive();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_ATOM, driver_mk_atom((char *)(primitive)), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_crypto_onetimeauth/2 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth, crypto_onetimeauth) {
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_onetimeauth, crypto_onetimeauth);

static int
LS_API_INIT(crypto_onetimeauth, crypto_onetimeauth)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, crypto_onetimeauth) * argv;
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

    keybytes = crypto_onetimeauth_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, crypto_onetimeauth))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth, crypto_onetimeauth) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, crypto_onetimeauth)));
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
LS_API_EXEC(crypto_onetimeauth, crypto_onetimeauth)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, crypto_onetimeauth) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth, crypto_onetimeauth);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_onetimeauth_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_onetimeauth(out, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(out);
}

/* crypto_onetimeauth_verify/3 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth, verify) {
    const unsigned char *h;
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_onetimeauth, verify);

static int
LS_API_INIT(crypto_onetimeauth, verify)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, verify) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    size_t inlen;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_onetimeauth_bytes();
    keybytes = crypto_onetimeauth_keybytes();

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

    x = (ErlDrvSizeT)(bytes + inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, verify))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth, verify) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, verify)));
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
LS_API_EXEC(crypto_onetimeauth, verify)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, verify) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth, verify);
    int r;

    r = crypto_onetimeauth_verify(argv->h, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_init/1 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth, init) {
    const unsigned char *key;
} LS_API_F_ARGV_T(crypto_onetimeauth, init);

static int
LS_API_INIT(crypto_onetimeauth, init)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, init) * argv;
    int type;
    int type_length;
    size_t keylen;
    ErlDrvSizeT x;
    void *p;

    keylen = crypto_onetimeauth_keybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keylen) {
        return -1;
    }

    x = (ErlDrvSizeT)(keylen + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, init))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth, init) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, init)));
    argv->key = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->key), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_onetimeauth, init)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, init) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth, init);
    size_t statebytes;
    crypto_onetimeauth_state *state;

    statebytes = crypto_onetimeauth_statebytes();

    state = (crypto_onetimeauth_state *)(sodium_malloc(statebytes));

    if (state == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_onetimeauth_init(state, argv->key);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_free(state);
}

/* crypto_onetimeauth_update/2 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth, update) {
    crypto_onetimeauth_state *state;
    const unsigned char *in;
    unsigned long long inlen;
} LS_API_F_ARGV_T(crypto_onetimeauth, update);

static int
LS_API_INIT(crypto_onetimeauth, update)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, update) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_onetimeauth_statebytes();

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

    x = (ErlDrvSizeT)(statebytes + type_length + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, update))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth, update) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, update)));
    argv->state = (crypto_onetimeauth_state *)(p);
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
LS_API_EXEC(crypto_onetimeauth, update)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, update) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth, update);
    size_t statebytes;

    statebytes = crypto_onetimeauth_statebytes();

    (void)crypto_onetimeauth_update(argv->state, argv->in, argv->inlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_final/1 */

typedef struct LS_API_F_ARGV(crypto_onetimeauth, final) {
    crypto_onetimeauth_state *state;
} LS_API_F_ARGV_T(crypto_onetimeauth, final);

static int
LS_API_INIT(crypto_onetimeauth, final)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, final) * argv;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_onetimeauth_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, final))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_onetimeauth, final) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_onetimeauth, final)));
    argv->state = (crypto_onetimeauth_state *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_onetimeauth, final)
{
    LS_API_F_ARGV_T(crypto_onetimeauth, final) * argv;
    LS_API_READ_ARGV(crypto_onetimeauth, final);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_onetimeauth_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_onetimeauth_final(argv->state, out);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_onetimeauth_keygen/0 */

static void
LS_API_EXEC(crypto_onetimeauth, keygen)
{
    unsigned char k[crypto_onetimeauth_KEYBYTES];

    (void)crypto_onetimeauth_keygen(k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request),         ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k),
                             crypto_onetimeauth_KEYBYTES, ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
