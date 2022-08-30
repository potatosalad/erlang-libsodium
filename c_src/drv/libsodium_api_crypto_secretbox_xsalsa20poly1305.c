// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_secretbox_xsalsa20poly1305.h"

static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, keybytes);
static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, noncebytes);
static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, macbytes);
static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, messagebytes_max);
static int LS_API_INIT(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305);
static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305);
static int LS_API_INIT(crypto_secretbox_xsalsa20poly1305, open);
static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, open);
static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, keygen);
static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, zerobytes);
static void LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, boxzerobytes);

libsodium_function_t libsodium_functions_crypto_secretbox_xsalsa20poly1305[] = {
    LS_API_R_ARG0(crypto_secretbox_xsalsa20poly1305, keybytes),
    LS_API_R_ARG0(crypto_secretbox_xsalsa20poly1305, noncebytes),
    LS_API_R_ARG0(crypto_secretbox_xsalsa20poly1305, macbytes),
    LS_API_R_ARG0(crypto_secretbox_xsalsa20poly1305, messagebytes_max),
    LS_API_R_ARGV(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305, 3),
    LS_API_R_ARGV(crypto_secretbox_xsalsa20poly1305, open, 3),
    LS_API_R_ARG0(crypto_secretbox_xsalsa20poly1305, keygen),
    LS_API_R_ARG0(crypto_secretbox_xsalsa20poly1305, zerobytes),
    LS_API_R_ARG0(crypto_secretbox_xsalsa20poly1305, boxzerobytes),
    {NULL}};

/* crypto_secretbox_xsalsa20poly1305_keybytes/0 */

LS_API_GET_SIZE(crypto_secretbox_xsalsa20poly1305, keybytes);

/* crypto_secretbox_xsalsa20poly1305_noncebytes/0 */

LS_API_GET_SIZE(crypto_secretbox_xsalsa20poly1305, noncebytes);

/* crypto_secretbox_xsalsa20poly1305_macbytes/0 */

LS_API_GET_SIZE(crypto_secretbox_xsalsa20poly1305, macbytes);

/* crypto_secretbox_xsalsa20poly1305_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_secretbox_xsalsa20poly1305, messagebytes_max);

/* crypto_secretbox_xsalsa20poly1305_crypto_secretbox_xsalsa20poly1305/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char n[crypto_secretbox_xsalsa20poly1305_NONCEBYTES];
    const unsigned char k[crypto_secretbox_xsalsa20poly1305_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305);

SODIUM_EXPORT
int crypto_secretbox_xsalsa20poly1305_crypto_secretbox_xsalsa20poly1305(unsigned char *c, const unsigned char *m,
                                                                        unsigned long long mlen, const unsigned char *n,
                                                                        const unsigned char *k) __attribute__((nonnull(1, 4, 5)));

static int
LS_API_INIT(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305)
{
    LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305) * argv;
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

    noncebytes = crypto_secretbox_xsalsa20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_xsalsa20poly1305_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305)));
    argv->m = (const unsigned char *)(p);

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
LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305)
{
    LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305) * argv;
    LS_API_READ_ARGV(crypto_secretbox_xsalsa20poly1305, crypto_secretbox_xsalsa20poly1305);

    size_t macbytes = crypto_secretbox_xsalsa20poly1305_macbytes();
    size_t clen = macbytes + argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_secretbox_xsalsa20poly1305(c, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_secretbox_xsalsa20poly1305_open/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox_xsalsa20poly1305, open) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char n[crypto_secretbox_xsalsa20poly1305_NONCEBYTES];
    const unsigned char k[crypto_secretbox_xsalsa20poly1305_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, open);

static int
LS_API_INIT(crypto_secretbox_xsalsa20poly1305, open)
{
    LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, open) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long clen;
    size_t noncebytes;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    clen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    noncebytes = crypto_secretbox_xsalsa20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_xsalsa20poly1305_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, open))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, open) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, open)));
    argv->c = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
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
LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, open)
{
    LS_API_F_ARGV_T(crypto_secretbox_xsalsa20poly1305, open) * argv;
    LS_API_READ_ARGV(crypto_secretbox_xsalsa20poly1305, open);

    size_t macbytes = crypto_secretbox_xsalsa20poly1305_macbytes();
    size_t mlen = argv->clen - macbytes;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_secretbox_xsalsa20poly1305_open(m, argv->c, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_secretbox_xsalsa20poly1305_keygen/0 */

static void
LS_API_EXEC(crypto_secretbox_xsalsa20poly1305, keygen)
{
    unsigned char k[crypto_secretbox_xsalsa20poly1305_KEYBYTES];

    (void)crypto_secretbox_xsalsa20poly1305_keygen(k);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k), crypto_secretbox_xsalsa20poly1305_KEYBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_secretbox_xsalsa20poly1305_zerobytes/0 */

LS_API_GET_SIZE(crypto_secretbox_xsalsa20poly1305, zerobytes);

/* crypto_secretbox_xsalsa20poly1305_boxzerobytes/0 */

LS_API_GET_SIZE(crypto_secretbox_xsalsa20poly1305, boxzerobytes);
