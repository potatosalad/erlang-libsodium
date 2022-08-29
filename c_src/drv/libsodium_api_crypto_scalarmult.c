// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_scalarmult.h"

static void LS_API_EXEC(crypto_scalarmult, bytes);
static void LS_API_EXEC(crypto_scalarmult, scalarbytes);
static void LS_API_EXEC(crypto_scalarmult, primitive);
static int LS_API_INIT(crypto_scalarmult, base);
static void LS_API_EXEC(crypto_scalarmult, base);
static int LS_API_INIT(crypto_scalarmult, crypto_scalarmult);
static void LS_API_EXEC(crypto_scalarmult, crypto_scalarmult);

libsodium_function_t libsodium_functions_crypto_scalarmult[] = {LS_API_R_ARG0(crypto_scalarmult, bytes),
                                                                LS_API_R_ARG0(crypto_scalarmult, scalarbytes),
                                                                LS_API_R_ARG0(crypto_scalarmult, primitive),
                                                                LS_API_R_ARGV(crypto_scalarmult, base, 1),
                                                                LS_API_R_ARGV(crypto_scalarmult, crypto_scalarmult, 2),
                                                                {NULL}};

/* crypto_scalarmult_bytes/0 */

LS_API_GET_SIZE(crypto_scalarmult, bytes);

/* crypto_scalarmult_scalarbytes/0 */

LS_API_GET_SIZE(crypto_scalarmult, scalarbytes);

/* crypto_scalarmult_primitive/0 */

LS_API_GET_ATOM(crypto_scalarmult, primitive);

/* crypto_scalarmult_base/1 */

typedef struct LS_API_F_ARGV(crypto_scalarmult, base) {
    const unsigned char *n;
} LS_API_F_ARGV_T(crypto_scalarmult, base);

static int
LS_API_INIT(crypto_scalarmult, base)
{
    LS_API_F_ARGV_T(crypto_scalarmult, base) * argv;
    int type;
    int type_length;
    size_t scalarbytes;
    ErlDrvSizeT x;
    void *p;

    scalarbytes = crypto_scalarmult_scalarbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != scalarbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(scalarbytes + (sizeof(LS_API_F_ARGV_T(crypto_scalarmult, base))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_scalarmult, base) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_scalarmult, base)));
    argv->n = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_scalarmult, base)
{
    LS_API_F_ARGV_T(crypto_scalarmult, base) * argv;
    LS_API_READ_ARGV(crypto_scalarmult, base);

    size_t bytes = crypto_scalarmult_bytes();
    unsigned char q[bytes];

    LS_SAFE_REPLY(crypto_scalarmult_base(q, argv->n),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(q), bytes, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(q, bytes);
}

/* crypto_scalarmult_crypto_scalarmult/2 */

typedef struct LS_API_F_ARGV(crypto_scalarmult, crypto_scalarmult) {
    const unsigned char *n;
    const unsigned char *p;
} LS_API_F_ARGV_T(crypto_scalarmult, crypto_scalarmult);

static int
LS_API_INIT(crypto_scalarmult, crypto_scalarmult)
{
    LS_API_F_ARGV_T(crypto_scalarmult, crypto_scalarmult) * argv;
    int skip;
    int type;
    int type_length;
    size_t scalarbytes;
    ErlDrvSizeT x;
    void *p;

    scalarbytes = crypto_scalarmult_scalarbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != scalarbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != scalarbytes) {
        return -1;
    }

    x = (ErlDrvSizeT)(scalarbytes + scalarbytes + (sizeof(LS_API_F_ARGV_T(crypto_scalarmult, crypto_scalarmult))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_scalarmult, crypto_scalarmult) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_scalarmult, crypto_scalarmult)));
    argv->n = (const unsigned char *)(p);
    p += scalarbytes;
    argv->p = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->p), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_scalarmult, crypto_scalarmult)
{
    LS_API_F_ARGV_T(crypto_scalarmult, crypto_scalarmult) * argv;
    LS_API_READ_ARGV(crypto_scalarmult, crypto_scalarmult);

    size_t bytes = crypto_scalarmult_bytes();
    unsigned char q[bytes];

    LS_SAFE_REPLY(crypto_scalarmult(q, argv->n, argv->p),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(q), bytes, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(q, bytes);
}
