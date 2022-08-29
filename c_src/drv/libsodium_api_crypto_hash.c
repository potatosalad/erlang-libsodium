// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_hash.h"

static void LS_API_EXEC(crypto_hash, bytes);
static int LS_API_INIT(crypto_hash, crypto_hash);
static void LS_API_EXEC(crypto_hash, crypto_hash);
static void LS_API_EXEC(crypto_hash, primitive);

libsodium_function_t libsodium_functions_crypto_hash[] = {
    LS_API_R_ARG0(crypto_hash, bytes), LS_API_R_ARGV(crypto_hash, crypto_hash, 1), LS_API_R_ARG0(crypto_hash, primitive), {NULL}};

/* crypto_hash_bytes/0 */

static void
LS_API_EXEC(crypto_hash, bytes)
{
    size_t bytes;

    bytes = crypto_hash_bytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(bytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_hash_crypto_hash/1 */

typedef struct LS_API_F_ARGV(crypto_hash, crypto_hash) {
    const unsigned char *in;
    unsigned long long inlen;
} LS_API_F_ARGV_T(crypto_hash, crypto_hash);

static int
LS_API_INIT(crypto_hash, crypto_hash)
{
    LS_API_F_ARGV_T(crypto_hash, crypto_hash) * argv;
    int type;
    int type_length;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    x = (ErlDrvSizeT)(type_length + (sizeof(LS_API_F_ARGV_T(crypto_hash, crypto_hash))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_hash, crypto_hash) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_hash, crypto_hash)));
    argv->in = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->inlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_hash, crypto_hash)
{
    LS_API_F_ARGV_T(crypto_hash, crypto_hash) * argv;
    LS_API_READ_ARGV(crypto_hash, crypto_hash);
    size_t bytes;
    unsigned char *out;

    bytes = crypto_hash_bytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_hash(out, argv->in, argv->inlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), bytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(out);
}

/* crypto_hash_primitive/0 */

static void
LS_API_EXEC(crypto_hash, primitive)
{
    const char *primitive;

    primitive = crypto_hash_primitive();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_ATOM, driver_mk_atom((char *)(primitive)), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
