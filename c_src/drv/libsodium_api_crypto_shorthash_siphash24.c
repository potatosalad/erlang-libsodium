// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_shorthash_siphash24.h"

static void LS_API_EXEC(crypto_shorthash_siphash24, bytes);
static void LS_API_EXEC(crypto_shorthash_siphash24, keybytes);
static int LS_API_INIT(crypto_shorthash_siphash24, crypto_shorthash_siphash24);
static void LS_API_EXEC(crypto_shorthash_siphash24, crypto_shorthash_siphash24);

libsodium_function_t libsodium_functions_crypto_shorthash_siphash24[] = {
    LS_API_R_ARG0(crypto_shorthash_siphash24, bytes),
    LS_API_R_ARG0(crypto_shorthash_siphash24, keybytes),
    LS_API_R_ARGV(crypto_shorthash_siphash24, crypto_shorthash_siphash24, 2),
    {NULL}};

/* crypto_shorthash_siphash24_bytes/0 */

static void
LS_API_EXEC(crypto_shorthash_siphash24, bytes)
{
    size_t bytes;

    bytes = crypto_shorthash_siphash24_bytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_shorthash_siphash24_keybytes/0 */

static void
LS_API_EXEC(crypto_shorthash_siphash24, keybytes)
{
    size_t keybytes;

    keybytes = crypto_shorthash_siphash24_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_shorthash_siphash24_crypto_shorthash_siphash24/1 */

typedef struct LS_API_F_ARGV(crypto_shorthash_siphash24, crypto_shorthash_siphash24) {
    const unsigned char *in;
    unsigned long long inlen;
    const unsigned char *k;
} LS_API_F_ARGV_T(crypto_shorthash_siphash24, crypto_shorthash_siphash24);

static int
LS_API_INIT(crypto_shorthash_siphash24, crypto_shorthash_siphash24)
{
    LS_API_F_ARGV_T(crypto_shorthash_siphash24, crypto_shorthash_siphash24) * argv;
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

    keybytes = crypto_shorthash_siphash24_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(inlen + keybytes + (sizeof(LS_API_F_ARGV_T(crypto_shorthash_siphash24, crypto_shorthash_siphash24))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_shorthash_siphash24, crypto_shorthash_siphash24) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_shorthash_siphash24, crypto_shorthash_siphash24)));
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
LS_API_EXEC(crypto_shorthash_siphash24, crypto_shorthash_siphash24)
{
    LS_API_F_ARGV_T(crypto_shorthash_siphash24, crypto_shorthash_siphash24) * argv;
    LS_API_READ_ARGV(crypto_shorthash_siphash24, crypto_shorthash_siphash24);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_shorthash_siphash24_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_shorthash_siphash24(out, argv->in, argv->inlen, argv->k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(out);
}
