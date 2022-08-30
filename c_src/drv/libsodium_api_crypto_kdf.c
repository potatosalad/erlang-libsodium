// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_kdf.h"

static void LS_API_EXEC(crypto_kdf, bytes_min);
static void LS_API_EXEC(crypto_kdf, bytes_max);
static void LS_API_EXEC(crypto_kdf, contextbytes);
static void LS_API_EXEC(crypto_kdf, keybytes);
static void LS_API_EXEC(crypto_kdf, primitive);
static int LS_API_INIT(crypto_kdf, derive_from_key);
static void LS_API_EXEC(crypto_kdf, derive_from_key);
static void LS_API_EXEC(crypto_kdf, keygen);

libsodium_function_t libsodium_functions_crypto_kdf[] = {
    LS_API_R_ARG0(crypto_kdf, bytes_min),    LS_API_R_ARG0(crypto_kdf, bytes_max),
    LS_API_R_ARG0(crypto_kdf, contextbytes), LS_API_R_ARG0(crypto_kdf, keybytes),
    LS_API_R_ARG0(crypto_kdf, primitive),    LS_API_R_ARGV(crypto_kdf, derive_from_key, 4),
    LS_API_R_ARG0(crypto_kdf, keygen),       {NULL}};

/* crypto_kdf_bytes_min/0 */

LS_API_GET_SIZE(crypto_kdf, bytes_min);

/* crypto_kdf_bytes_max/0 */

LS_API_GET_SIZE(crypto_kdf, bytes_max);

/* crypto_kdf_contextbytes/0 */

LS_API_GET_SIZE(crypto_kdf, contextbytes);

/* crypto_kdf_keybytes/0 */

LS_API_GET_SIZE(crypto_kdf, keybytes);

/* crypto_kdf_primitive/0 */

LS_API_GET_STR(crypto_kdf, primitive);

/* crypto_kdf_derive_from_key/4 */

typedef struct LS_API_F_ARGV(crypto_kdf, derive_from_key) {
    size_t subkey_len;
    uint64_t subkey_id;
    const char ctx[crypto_kdf_CONTEXTBYTES];
    const unsigned char key[crypto_kdf_KEYBYTES];
} LS_API_F_ARGV_T(crypto_kdf, derive_from_key);

static int
LS_API_INIT(crypto_kdf, derive_from_key)
{
    LS_API_F_ARGV_T(crypto_kdf, derive_from_key) * argv;
    int skip;
    int type;
    int type_length;
    size_t subkey_len;
    uint64_t subkey_id;
    size_t contextbytes;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_decode_ulong(buffer, index, (unsigned long *)&(subkey_len)) < 0) {
        return -1;
    }

    if (ei_decode_ulonglong(buffer, index, (unsigned long long *)&(subkey_id)) < 0) {
        return -1;
    }

    contextbytes = crypto_kdf_contextbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != contextbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_kdf_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_kdf, derive_from_key))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_kdf, derive_from_key) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_kdf, derive_from_key)));
    argv->subkey_len = subkey_len;
    argv->subkey_id = subkey_id;

    if (ei_decode_binary(buffer, index, (void *)(argv->ctx), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->key), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_kdf, derive_from_key)
{
    LS_API_F_ARGV_T(crypto_kdf, derive_from_key) * argv;
    LS_API_READ_ARGV(crypto_kdf, derive_from_key);
    unsigned char *subkey = NULL;

    subkey = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->subkey_len)));

    if (subkey == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(
        crypto_kdf_derive_from_key(subkey, argv->subkey_len, argv->subkey_id, argv->ctx, argv->key),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(subkey), argv->subkey_len, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(subkey, argv->subkey_len);
    (void)driver_free((void *)subkey);
}

/* crypto_kdf_keygen/0 */

static void
LS_API_EXEC(crypto_kdf, keygen)
{
    unsigned char k[crypto_kdf_KEYBYTES];

    (void)crypto_kdf_keygen(k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k), crypto_kdf_KEYBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
