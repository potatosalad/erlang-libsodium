// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_stream_salsa20.h"

static void LS_API_EXEC(crypto_stream_salsa20, keybytes);
static void LS_API_EXEC(crypto_stream_salsa20, noncebytes);
static void LS_API_EXEC(crypto_stream_salsa20, messagebytes_max);
static int LS_API_INIT(crypto_stream_salsa20, crypto_stream_salsa20);
static void LS_API_EXEC(crypto_stream_salsa20, crypto_stream_salsa20);
static int LS_API_INIT(crypto_stream_salsa20, xor);
static void LS_API_EXEC(crypto_stream_salsa20, xor);
static int LS_API_INIT(crypto_stream_salsa20, xor_ic);
static void LS_API_EXEC(crypto_stream_salsa20, xor_ic);
static void LS_API_EXEC(crypto_stream_salsa20, keygen);

libsodium_function_t libsodium_functions_crypto_stream_salsa20[] = {
    LS_API_R_ARG0(crypto_stream_salsa20, keybytes),         LS_API_R_ARG0(crypto_stream_salsa20, noncebytes),
    LS_API_R_ARG0(crypto_stream_salsa20, messagebytes_max), LS_API_R_ARGV(crypto_stream_salsa20, crypto_stream_salsa20, 3),
    LS_API_R_ARGV(crypto_stream_salsa20, xor, 3),           LS_API_R_ARGV(crypto_stream_salsa20, xor_ic, 4),
    LS_API_R_ARG0(crypto_stream_salsa20, keygen),           {NULL}};

/* crypto_stream_salsa20_keybytes/0 */

static void
LS_API_EXEC(crypto_stream_salsa20, keybytes)
{
    size_t keybytes;

    keybytes = crypto_stream_salsa20_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_salsa20_noncebytes/0 */

static void
LS_API_EXEC(crypto_stream_salsa20, noncebytes)
{
    size_t noncebytes;

    noncebytes = crypto_stream_salsa20_noncebytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(noncebytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_salsa20_messagebytes_max/0 */

static void
LS_API_EXEC(crypto_stream_salsa20, messagebytes_max)
{
    size_t messagebytes_max;

    messagebytes_max = crypto_stream_salsa20_messagebytes_max();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(messagebytes_max), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_salsa20_crypto_stream_salsa20/3 */

typedef struct LS_API_F_ARGV(crypto_stream_salsa20, crypto_stream_salsa20) {
    unsigned long long clen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_stream_salsa20, crypto_stream_salsa20);

static int
LS_API_INIT(crypto_stream_salsa20, crypto_stream_salsa20)
{
    LS_API_F_ARGV_T(crypto_stream_salsa20, crypto_stream_salsa20) * argv;
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

    noncebytes = crypto_stream_salsa20_noncebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_stream_salsa20_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(noncebytes + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa20, crypto_stream_salsa20))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_stream_salsa20, crypto_stream_salsa20) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa20, crypto_stream_salsa20)));
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
LS_API_EXEC(crypto_stream_salsa20, crypto_stream_salsa20)
{
    LS_API_F_ARGV_T(crypto_stream_salsa20, crypto_stream_salsa20) * argv;
    LS_API_READ_ARGV(crypto_stream_salsa20, crypto_stream_salsa20);
    unsigned char *c;

    c = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->clen)));

    if (c == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_stream_salsa20(c, argv->clen, argv->n, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), argv->clen, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(c);
}

/* crypto_stream_salsa20_xor/3 */

typedef struct LS_API_F_ARGV(crypto_stream_salsa20, xor) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_stream_salsa20, xor);

static int
LS_API_INIT(crypto_stream_salsa20, xor)
{
    LS_API_F_ARGV_T(crypto_stream_salsa20, xor) * argv;
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

    noncebytes = crypto_stream_salsa20_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_stream_salsa20_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa20, xor))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_stream_salsa20, xor) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa20, xor)));
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
LS_API_EXEC(crypto_stream_salsa20, xor)
{
    LS_API_F_ARGV_T(crypto_stream_salsa20, xor) * argv;
    LS_API_READ_ARGV(crypto_stream_salsa20, xor);
    unsigned char *c;

    c = (unsigned char *)(argv->m);

    (void)crypto_stream_salsa20_xor(c, argv->m, argv->mlen, argv->n, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), argv->mlen, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_salsa20_xor_ic/4 */

typedef struct LS_API_F_ARGV(crypto_stream_salsa20, xor_ic) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *n;
    uint64_t ic;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_stream_salsa20, xor_ic);

static int
LS_API_INIT(crypto_stream_salsa20, xor_ic)
{
    LS_API_F_ARGV_T(crypto_stream_salsa20, xor_ic) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long mlen;
    size_t noncebytes;
    uint64_t ic;
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

    noncebytes = crypto_stream_salsa20_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(ic)) < 0) {
        return -1;
    }

    keybytes = crypto_stream_salsa20_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + noncebytes + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa20, xor_ic))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_stream_salsa20, xor_ic) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_stream_salsa20, xor_ic)));
    argv->m = (const unsigned char *)(p);
    p += mlen;
    argv->n = (const unsigned char *)(p);
    argv->ic = ic;
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

    if (ei_skip_term(buffer, index) < 0) {
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
LS_API_EXEC(crypto_stream_salsa20, xor_ic)
{
    LS_API_F_ARGV_T(crypto_stream_salsa20, xor_ic) * argv;
    LS_API_READ_ARGV(crypto_stream_salsa20, xor_ic);
    unsigned char *c;

    c = (unsigned char *)(argv->m);

    (void)crypto_stream_salsa20_xor_ic(c, argv->m, argv->mlen, argv->n, argv->ic, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), argv->mlen, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_salsa20_keygen/0 */

static void
LS_API_EXEC(crypto_stream_salsa20, keygen)
{
    unsigned char k[crypto_stream_salsa20_KEYBYTES];

    (void)crypto_stream_salsa20_keygen(k);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k), crypto_stream_salsa20_KEYBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
