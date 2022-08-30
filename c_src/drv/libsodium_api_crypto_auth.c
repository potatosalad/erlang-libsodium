// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_auth.h"

static void LS_API_EXEC(crypto_auth, bytes);
static void LS_API_EXEC(crypto_auth, keybytes);
static void LS_API_EXEC(crypto_auth, primitive);
static int LS_API_INIT(crypto_auth, crypto_auth);
static void LS_API_EXEC(crypto_auth, crypto_auth);
static int LS_API_INIT(crypto_auth, verify);
static void LS_API_EXEC(crypto_auth, verify);
static void LS_API_EXEC(crypto_auth, keygen);

libsodium_function_t libsodium_functions_crypto_auth[] = {LS_API_R_ARG0(crypto_auth, bytes),
                                                          LS_API_R_ARG0(crypto_auth, keybytes),
                                                          LS_API_R_ARG0(crypto_auth, primitive),
                                                          LS_API_R_ARGV(crypto_auth, crypto_auth, 2),
                                                          LS_API_R_ARGV(crypto_auth, verify, 3),
                                                          LS_API_R_ARG0(crypto_auth, keygen),
                                                          {NULL}};

/* crypto_auth_bytes/0 */

static void
LS_API_EXEC(crypto_auth, bytes)
{
    size_t bytes;

    bytes = crypto_auth_bytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_keybytes/0 */

static void
LS_API_EXEC(crypto_auth, keybytes)
{
    size_t keybytes;

    keybytes = crypto_auth_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_primitive/0 */

static void
LS_API_EXEC(crypto_auth, primitive)
{
    const char *primitive;

    primitive = crypto_auth_primitive();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_ATOM, driver_mk_atom((char *)(primitive)), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_crypto_auth/2 */

typedef struct LS_API_F_ARGV(crypto_auth, crypto_auth) {
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_auth, crypto_auth);

static int
LS_API_INIT(crypto_auth, crypto_auth)
{
    LS_API_F_ARGV_T(crypto_auth, crypto_auth) * argv;
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

    keybytes = crypto_auth_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_auth, crypto_auth))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_auth, crypto_auth) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_auth, crypto_auth)));
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
LS_API_EXEC(crypto_auth, crypto_auth)
{
    LS_API_F_ARGV_T(crypto_auth, crypto_auth) * argv;
    LS_API_READ_ARGV(crypto_auth, crypto_auth);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_auth_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_auth(out, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(out);
}

/* crypto_auth_verify/3 */

typedef struct LS_API_F_ARGV(crypto_auth, verify) {
    const unsigned char *h;
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_auth, verify);

static int
LS_API_INIT(crypto_auth, verify)
{
    LS_API_F_ARGV_T(crypto_auth, verify) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    size_t inlen;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_auth_bytes();
    keybytes = crypto_auth_keybytes();

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

    x = (ErlDrvSizeT)(bytes + inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_auth, verify))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_auth, verify) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_auth, verify)));
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
LS_API_EXEC(crypto_auth, verify)
{
    LS_API_F_ARGV_T(crypto_auth, verify) * argv;
    LS_API_READ_ARGV(crypto_auth, verify);
    int r;

    r = crypto_auth_verify(argv->h, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_auth_keygen/0 */

static void
LS_API_EXEC(crypto_auth, keygen)
{
    unsigned char k[crypto_auth_KEYBYTES];

    (void)crypto_auth_keygen(k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k), crypto_auth_KEYBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
