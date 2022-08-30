// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_kx.h"

static void LS_API_EXEC(crypto_kx, publickeybytes);
static void LS_API_EXEC(crypto_kx, secretkeybytes);
static void LS_API_EXEC(crypto_kx, seedbytes);
static void LS_API_EXEC(crypto_kx, sessionkeybytes);
static void LS_API_EXEC(crypto_kx, primitive);
static int LS_API_INIT(crypto_kx, seed_keypair);
static void LS_API_EXEC(crypto_kx, seed_keypair);
static void LS_API_EXEC(crypto_kx, keypair);
static int LS_API_INIT(crypto_kx, client_session_keys);
static void LS_API_EXEC(crypto_kx, client_session_keys);
static int LS_API_INIT(crypto_kx, server_session_keys);
static void LS_API_EXEC(crypto_kx, server_session_keys);

libsodium_function_t libsodium_functions_crypto_kx[] = {LS_API_R_ARG0(crypto_kx, publickeybytes),
                                                        LS_API_R_ARG0(crypto_kx, secretkeybytes),
                                                        LS_API_R_ARG0(crypto_kx, seedbytes),
                                                        LS_API_R_ARG0(crypto_kx, sessionkeybytes),
                                                        LS_API_R_ARG0(crypto_kx, primitive),
                                                        LS_API_R_ARGV(crypto_kx, seed_keypair, 1),
                                                        LS_API_R_ARG0(crypto_kx, keypair),
                                                        LS_API_R_ARGV(crypto_kx, client_session_keys, 3),
                                                        LS_API_R_ARGV(crypto_kx, server_session_keys, 3),
                                                        {NULL}};

/* crypto_kx_publickeybytes/0 */

LS_API_GET_SIZE(crypto_kx, publickeybytes);

/* crypto_kx_secretkeybytes/0 */

LS_API_GET_SIZE(crypto_kx, secretkeybytes);

/* crypto_kx_seedbytes/0 */

LS_API_GET_SIZE(crypto_kx, seedbytes);

/* crypto_kx_sessionkeybytes/0 */

LS_API_GET_SIZE(crypto_kx, sessionkeybytes);

/* crypto_kx_primitive/0 */

LS_API_GET_STR(crypto_kx, primitive);

/* crypto_kx_seed_keypair/1 */

typedef struct LS_API_F_ARGV(crypto_kx, seed_keypair) {
    const unsigned char seed[crypto_kx_SEEDBYTES];
} LS_API_F_ARGV_T(crypto_kx, seed_keypair);

static int
LS_API_INIT(crypto_kx, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_kx, seed_keypair) * argv;
    int skip;
    int type;
    int type_length;
    size_t seedbytes;
    ErlDrvSizeT x;
    void *p;

    seedbytes = crypto_kx_seedbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != seedbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_kx, seed_keypair))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_kx, seed_keypair) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_kx, seed_keypair)));

    if (ei_decode_binary(buffer, index, (void *)(argv->seed), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_kx, seed_keypair)
{
    LS_API_F_ARGV_T(crypto_kx, seed_keypair) * argv;
    LS_API_READ_ARGV(crypto_kx, seed_keypair);
    unsigned char pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sk[crypto_kx_SECRETKEYBYTES];

    LS_SAFE_REPLY(
        crypto_kx_seed_keypair(pk, sk, argv->seed),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), crypto_kx_PUBLICKEYBYTES, ERL_DRV_BUF2BINARY,
                    (ErlDrvTermData)(sk), crypto_kx_SECRETKEYBYTES, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(pk, crypto_kx_PUBLICKEYBYTES);
    (void)sodium_memzero(sk, crypto_kx_SECRETKEYBYTES);
}

/* crypto_kx_keypair/0 */

static void
LS_API_EXEC(crypto_kx, keypair)
{
    unsigned char pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sk[crypto_kx_SECRETKEYBYTES];

    LS_SAFE_REPLY(
        crypto_kx_keypair(pk, sk),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), crypto_kx_PUBLICKEYBYTES, ERL_DRV_BUF2BINARY,
                    (ErlDrvTermData)(sk), crypto_kx_SECRETKEYBYTES, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(pk, crypto_kx_PUBLICKEYBYTES);
    (void)sodium_memzero(sk, crypto_kx_SECRETKEYBYTES);
}

/* crypto_kx_client_session_keys/3 */

typedef struct LS_API_F_ARGV(crypto_kx, client_session_keys) {
    const unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    const unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    const unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
} LS_API_F_ARGV_T(crypto_kx, client_session_keys);

static int
LS_API_INIT(crypto_kx, client_session_keys)
{
    LS_API_F_ARGV_T(crypto_kx, client_session_keys) * argv;
    int skip;
    int type;
    int type_length;
    size_t publickeybytes;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    publickeybytes = crypto_kx_publickeybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_kx_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_kx, client_session_keys))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_kx, client_session_keys) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_kx, client_session_keys)));

    if (ei_decode_binary(buffer, index, (void *)(argv->client_pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->client_sk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->server_pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_kx, client_session_keys)
{
    LS_API_F_ARGV_T(crypto_kx, client_session_keys) * argv;
    LS_API_READ_ARGV(crypto_kx, client_session_keys);
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];

    LS_SAFE_REPLY(
        crypto_kx_client_session_keys(rx, tx, argv->client_pk, argv->client_sk, argv->server_pk),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(rx), crypto_kx_SESSIONKEYBYTES, ERL_DRV_BUF2BINARY,
                    (ErlDrvTermData)(tx), crypto_kx_SESSIONKEYBYTES, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(rx, crypto_kx_SESSIONKEYBYTES);
    (void)sodium_memzero(tx, crypto_kx_SESSIONKEYBYTES);
}

/* crypto_kx_server_session_keys/1 */

typedef struct LS_API_F_ARGV(crypto_kx, server_session_keys) {
    const unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    const unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
    const unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
} LS_API_F_ARGV_T(crypto_kx, server_session_keys);

static int
LS_API_INIT(crypto_kx, server_session_keys)
{
    LS_API_F_ARGV_T(crypto_kx, server_session_keys) * argv;
    int skip;
    int type;
    int type_length;
    size_t publickeybytes;
    size_t secretkeybytes;
    ErlDrvSizeT x;
    void *p;

    publickeybytes = crypto_kx_publickeybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    secretkeybytes = crypto_kx_secretkeybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != secretkeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != publickeybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_kx, server_session_keys))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_kx, server_session_keys) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_kx, server_session_keys)));

    if (ei_decode_binary(buffer, index, (void *)(argv->server_pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->server_sk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->client_pk), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_kx, server_session_keys)
{
    LS_API_F_ARGV_T(crypto_kx, server_session_keys) * argv;
    LS_API_READ_ARGV(crypto_kx, server_session_keys);
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];

    LS_SAFE_REPLY(
        crypto_kx_server_session_keys(rx, tx, argv->server_pk, argv->server_sk, argv->client_pk),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(rx), crypto_kx_SESSIONKEYBYTES, ERL_DRV_BUF2BINARY,
                    (ErlDrvTermData)(tx), crypto_kx_SESSIONKEYBYTES, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(rx, crypto_kx_SESSIONKEYBYTES);
    (void)sodium_memzero(tx, crypto_kx_SESSIONKEYBYTES);
}
