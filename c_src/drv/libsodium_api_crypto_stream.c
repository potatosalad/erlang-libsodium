// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_stream.h"

static void LS_API_EXEC(crypto_stream, keybytes);
static void LS_API_EXEC(crypto_stream, noncebytes);
static void LS_API_EXEC(crypto_stream, messagebytes_max);
static void LS_API_EXEC(crypto_stream, primitive);
static int LS_API_INIT(crypto_stream, crypto_stream);
static void LS_API_EXEC(crypto_stream, crypto_stream);
static int LS_API_INIT(crypto_stream, xor);
static void LS_API_EXEC(crypto_stream, xor);
static void LS_API_EXEC(crypto_stream, keygen);

libsodium_function_t libsodium_functions_crypto_stream[] = {
    LS_API_R_ARG0(crypto_stream, keybytes),         LS_API_R_ARG0(crypto_stream, noncebytes),
    LS_API_R_ARG0(crypto_stream, messagebytes_max), LS_API_R_ARG0(crypto_stream, primitive),
    LS_API_R_ARGV(crypto_stream, crypto_stream, 3), LS_API_R_ARGV(crypto_stream, xor, 3),
    LS_API_R_ARG0(crypto_stream, keygen),           {NULL}};

/* crypto_stream_keybytes/0 */

static void
LS_API_EXEC(crypto_stream, keybytes)
{
    size_t keybytes;

    keybytes = crypto_stream_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_noncebytes/0 */

static void
LS_API_EXEC(crypto_stream, noncebytes)
{
    size_t noncebytes;

    noncebytes = crypto_stream_noncebytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(noncebytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_messagebytes_max/0 */

static void
LS_API_EXEC(crypto_stream, messagebytes_max)
{
    size_t messagebytes_max;

    messagebytes_max = crypto_stream_messagebytes_max();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(messagebytes_max), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_primitive/0 */

static void
LS_API_EXEC(crypto_stream, primitive)
{
    const char *primitive;

    primitive = crypto_stream_primitive();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_ATOM, driver_mk_atom((char *)(primitive)), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_crypto_stream/3 */

typedef struct LS_API_F_ARGV(crypto_stream, crypto_stream) {
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_stream, crypto_stream);

static int
LS_API_INIT(crypto_stream, crypto_stream)
{
    LS_API_F_ARGV_T(crypto_stream, crypto_stream) * argv;
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

    noncebytes = crypto_stream_noncebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_stream_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(noncebytes + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_stream, crypto_stream))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_stream, crypto_stream) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_stream, crypto_stream)));
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
LS_API_EXEC(crypto_stream, crypto_stream)
{
    LS_API_F_ARGV_T(crypto_stream, crypto_stream) * argv;
    LS_API_READ_ARGV(crypto_stream, crypto_stream);
    unsigned char *c;

    c = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->clen)));

    if (c == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_stream(c, argv->clen, argv->n, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), argv->clen, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(c);
}

/* crypto_stream_xor/3 */

typedef struct LS_API_F_ARGV(crypto_stream, xor) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_stream, xor);

static int
LS_API_INIT(crypto_stream, xor)
{
    LS_API_F_ARGV_T(crypto_stream, xor) * argv;
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

    noncebytes = crypto_stream_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_stream_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_stream, xor))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_stream, xor) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_stream, xor)));
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
LS_API_EXEC(crypto_stream, xor)
{
    LS_API_F_ARGV_T(crypto_stream, xor) * argv;
    LS_API_READ_ARGV(crypto_stream, xor);
    unsigned char *c;

    c = (unsigned char *)(argv->m);

    (void)crypto_stream_xor(c, argv->m, argv->mlen, argv->n, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), argv->mlen, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_keygen/0 */

static void
LS_API_EXEC(crypto_stream, keygen)
{
    unsigned char k[crypto_stream_KEYBYTES];

    (void)crypto_stream_keygen(k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request),    ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k),
                             crypto_stream_KEYBYTES, ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
