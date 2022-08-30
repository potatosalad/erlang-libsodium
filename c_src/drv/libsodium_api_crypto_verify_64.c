// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_verify_64.h"

static void LS_API_EXEC(crypto_verify_64, bytes);
static int LS_API_INIT(crypto_verify_64, crypto_verify_64);
static void LS_API_EXEC(crypto_verify_64, crypto_verify_64);

libsodium_function_t libsodium_functions_crypto_verify_64[] = {
    LS_API_R_ARG0(crypto_verify_64, bytes), LS_API_R_ARGV(crypto_verify_64, crypto_verify_64, 2), {NULL}};

/* crypto_verify_64_bytes/0 */

LS_API_GET_SIZE(crypto_verify_64, bytes);

/* crypto_verify_64_crypto_verify_64/2 */

typedef struct LS_API_F_ARGV(crypto_verify_64, crypto_verify_64) {
    const unsigned char x[crypto_verify_64_BYTES];
    const unsigned char y[crypto_verify_64_BYTES];
} LS_API_F_ARGV_T(crypto_verify_64, crypto_verify_64);

static int
LS_API_INIT(crypto_verify_64, crypto_verify_64)
{
    LS_API_F_ARGV_T(crypto_verify_64, crypto_verify_64) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_verify_64_bytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != bytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != bytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_verify_64, crypto_verify_64))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_verify_64, crypto_verify_64) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_verify_64, crypto_verify_64)));

    if (ei_decode_binary(buffer, index, (void *)(argv->x), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->y), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_verify_64, crypto_verify_64)
{
    LS_API_F_ARGV_T(crypto_verify_64, crypto_verify_64) * argv;
    LS_API_READ_ARGV(crypto_verify_64, crypto_verify_64);

    int r = crypto_verify_64(argv->x, argv->y);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
