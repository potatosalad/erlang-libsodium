// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_stream_salsa208.h"

static void LS_API_EXEC(crypto_stream_salsa208, keybytes);
static void LS_API_EXEC(crypto_stream_salsa208, noncebytes);
static int LS_API_INIT(crypto_stream_salsa208, crypto_stream_salsa208);
static void LS_API_EXEC(crypto_stream_salsa208, crypto_stream_salsa208);
static int LS_API_INIT(crypto_stream_salsa208, xor);
static void LS_API_EXEC(crypto_stream_salsa208, xor);

libsodium_function_t libsodium_functions_crypto_stream_salsa208[] = {
    LS_API_R_ARG0(crypto_stream_salsa208, keybytes),
    LS_API_R_ARG0(crypto_stream_salsa208, noncebytes),
    LS_API_R_ARGV(crypto_stream_salsa208, crypto_stream_salsa208, 3),
    LS_API_R_ARGV(crypto_stream_salsa208, xor, 3),
    {NULL}};

/* crypto_stream_salsa208_keybytes/0 */

static void
LS_API_EXEC(crypto_stream_salsa208, keybytes)
{
    size_t keybytes;

    keybytes = crypto_stream_salsa208_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_salsa208_noncebytes/0 */

static void
LS_API_EXEC(crypto_stream_salsa208, noncebytes)
{
    size_t noncebytes;

    noncebytes = crypto_stream_salsa208_noncebytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(noncebytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_salsa208_crypto_stream_salsa208/3 */

typedef struct LS_API_F_ARGV(crypto_stream_salsa208, crypto_stream_salsa208) {
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_stream_salsa208, crypto_stream_salsa208);

static int
LS_API_INIT(crypto_stream_salsa208, crypto_stream_salsa208)
{
    LS_API_F_ARGV_T(crypto_stream_salsa208, crypto_stream_salsa208) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long clen;
    size_t noncebytes;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_decode_ulong(buffer, index, (unsigned long *)&(clen)) < 0) {
        return -1;
    }

    noncebytes = crypto_stream_salsa208_noncebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_stream_salsa208_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(noncebytes + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa208, crypto_stream_salsa208))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_stream_salsa208, crypto_stream_salsa208) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa208, crypto_stream_salsa208)));
    argv->clen = clen;
    argv->n = (const unsigned char *)(p);
    p += noncebytes;
    argv->k = (const unsigned char *)(p);

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
LS_API_EXEC(crypto_stream_salsa208, crypto_stream_salsa208)
{
    LS_API_F_ARGV_T(crypto_stream_salsa208, crypto_stream_salsa208) * argv;
    LS_API_READ_ARGV(crypto_stream_salsa208, crypto_stream_salsa208);
    unsigned char *c;

    c = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->clen)));

    if (c == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_stream_salsa208(c, argv->clen, argv->n, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), argv->clen, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(c);
}

/* crypto_stream_salsa208_xor/3 */

typedef struct LS_API_F_ARGV(crypto_stream_salsa208, xor) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_stream_salsa208, xor);

static int
LS_API_INIT(crypto_stream_salsa208, xor)
{
    LS_API_F_ARGV_T(crypto_stream_salsa208, xor) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
    size_t noncebytes;
    size_t keybytes;
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

    noncebytes = crypto_stream_salsa208_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_stream_salsa208_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa208, xor))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_stream_salsa208, xor) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa208, xor)));
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
LS_API_EXEC(crypto_stream_salsa208, xor)
{
    LS_API_F_ARGV_T(crypto_stream_salsa208, xor) * argv;
    LS_API_READ_ARGV(crypto_stream_salsa208, xor);
    unsigned char *c;

    c = (unsigned char *)(argv->m);

    (void)crypto_stream_salsa208_xor(c, argv->m, argv->mlen, argv->n, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), argv->mlen, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
