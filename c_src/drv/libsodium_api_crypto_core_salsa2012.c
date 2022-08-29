// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_core_salsa2012.h"

static void LS_API_EXEC(crypto_core_salsa2012, outputbytes);
static void LS_API_EXEC(crypto_core_salsa2012, inputbytes);
static void LS_API_EXEC(crypto_core_salsa2012, keybytes);
static void LS_API_EXEC(crypto_core_salsa2012, constbytes);
static int LS_API_INIT(crypto_core_salsa2012, crypto_core_salsa2012);
static void LS_API_EXEC(crypto_core_salsa2012, crypto_core_salsa2012);

libsodium_function_t libsodium_functions_crypto_core_salsa2012[] = {LS_API_R_ARG0(crypto_core_salsa2012, outputbytes),
                                                                    LS_API_R_ARG0(crypto_core_salsa2012, inputbytes),
                                                                    LS_API_R_ARG0(crypto_core_salsa2012, keybytes),
                                                                    LS_API_R_ARG0(crypto_core_salsa2012, constbytes),
                                                                    LS_API_R_ARGV(crypto_core_salsa2012, crypto_core_salsa2012, 3),
                                                                    {NULL}};

/* crypto_core_salsa2012_outputbytes/0 */

static void
LS_API_EXEC(crypto_core_salsa2012, outputbytes)
{
    size_t outputbytes;

    outputbytes = crypto_core_salsa2012_outputbytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(outputbytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_core_salsa2012_inputbytes/0 */

static void
LS_API_EXEC(crypto_core_salsa2012, inputbytes)
{
    size_t inputbytes;

    inputbytes = crypto_core_salsa2012_inputbytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(inputbytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_core_salsa2012_keybytes/0 */

static void
LS_API_EXEC(crypto_core_salsa2012, keybytes)
{
    size_t keybytes;

    keybytes = crypto_core_salsa2012_keybytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(keybytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_core_salsa2012_constbytes/0 */

static void
LS_API_EXEC(crypto_core_salsa2012, constbytes)
{
    size_t constbytes;

    constbytes = crypto_core_salsa2012_constbytes();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(constbytes), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_core_salsa2012_crypto_core_salsa2012/2 */

typedef struct LS_API_F_ARGV(crypto_core_salsa2012, crypto_core_salsa2012) {
    const unsigned char *in;
    const unsigned char *k;
    const unsigned char *c;
} LS_API_F_ARGV_T(crypto_core_salsa2012, crypto_core_salsa2012);

static int
LS_API_INIT(crypto_core_salsa2012, crypto_core_salsa2012)
{
    LS_API_F_ARGV_T(crypto_core_salsa2012, crypto_core_salsa2012) * argv;
    int skip;
    int type;
    int type_length;
    size_t inputbytes;
    size_t keybytes;
    size_t constbytes;
    ErlDrvSizeT x;
    void *p;

    inputbytes = crypto_core_salsa2012_inputbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != inputbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_core_salsa2012_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    constbytes = crypto_core_salsa2012_constbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != constbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(inputbytes + keybytes + constbytes + (sizeof(LS_API_F_ARGV_T(crypto_core_salsa2012, crypto_core_salsa2012))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_salsa2012, crypto_core_salsa2012) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_salsa2012, crypto_core_salsa2012)));
    argv->in = (const unsigned char *)(p);
    p += inputbytes;
    argv->k = (const unsigned char *)(p);
    p += keybytes;
    argv->c = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->in), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->c), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_salsa2012, crypto_core_salsa2012)
{
    LS_API_F_ARGV_T(crypto_core_salsa2012, crypto_core_salsa2012) * argv;
    LS_API_READ_ARGV(crypto_core_salsa2012, crypto_core_salsa2012);
    size_t outputbytes;
    unsigned char *out;

    outputbytes = crypto_core_salsa2012_outputbytes();
    out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(outputbytes)));

    if (out == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)crypto_core_salsa2012(out, argv->in, argv->k, argv->c);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), outputbytes, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(out);
}
