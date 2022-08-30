// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_secretbox_xchacha20poly1305.h"

static void LS_API_EXEC(crypto_secretbox_xchacha20poly1305, keybytes);
static void LS_API_EXEC(crypto_secretbox_xchacha20poly1305, noncebytes);
static void LS_API_EXEC(crypto_secretbox_xchacha20poly1305, macbytes);
static void LS_API_EXEC(crypto_secretbox_xchacha20poly1305, messagebytes_max);
static int LS_API_INIT(crypto_secretbox_xchacha20poly1305, easy);
static void LS_API_EXEC(crypto_secretbox_xchacha20poly1305, easy);
static int LS_API_INIT(crypto_secretbox_xchacha20poly1305, open_easy);
static void LS_API_EXEC(crypto_secretbox_xchacha20poly1305, open_easy);
static int LS_API_INIT(crypto_secretbox_xchacha20poly1305, detached);
static void LS_API_EXEC(crypto_secretbox_xchacha20poly1305, detached);
static int LS_API_INIT(crypto_secretbox_xchacha20poly1305, open_detached);
static void LS_API_EXEC(crypto_secretbox_xchacha20poly1305, open_detached);

libsodium_function_t libsodium_functions_crypto_secretbox_xchacha20poly1305[] = {
    LS_API_R_ARG0(crypto_secretbox_xchacha20poly1305, keybytes),
    LS_API_R_ARG0(crypto_secretbox_xchacha20poly1305, noncebytes),
    LS_API_R_ARG0(crypto_secretbox_xchacha20poly1305, macbytes),
    LS_API_R_ARG0(crypto_secretbox_xchacha20poly1305, messagebytes_max),
    LS_API_R_ARGV(crypto_secretbox_xchacha20poly1305, easy, 3),
    LS_API_R_ARGV(crypto_secretbox_xchacha20poly1305, open_easy, 3),
    LS_API_R_ARGV(crypto_secretbox_xchacha20poly1305, detached, 3),
    LS_API_R_ARGV(crypto_secretbox_xchacha20poly1305, open_detached, 4),
    {NULL}};

/* crypto_secretbox_xchacha20poly1305_keybytes/0 */

LS_API_GET_SIZE(crypto_secretbox_xchacha20poly1305, keybytes);

/* crypto_secretbox_xchacha20poly1305_noncebytes/0 */

LS_API_GET_SIZE(crypto_secretbox_xchacha20poly1305, noncebytes);

/* crypto_secretbox_xchacha20poly1305_macbytes/0 */

LS_API_GET_SIZE(crypto_secretbox_xchacha20poly1305, macbytes);

/* crypto_secretbox_xchacha20poly1305_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_secretbox_xchacha20poly1305, messagebytes_max);

/* crypto_secretbox_xchacha20poly1305_easy/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox_xchacha20poly1305, easy) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char n[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
    const unsigned char k[crypto_secretbox_xchacha20poly1305_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, easy);

SODIUM_EXPORT
int crypto_secretbox_xchacha20poly1305_easy(unsigned char *c, const unsigned char *m, unsigned long long mlen,
                                            const unsigned char *n, const unsigned char *k) __attribute__((nonnull(1, 4, 5)));

static int
LS_API_INIT(crypto_secretbox_xchacha20poly1305, easy)
{
    LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, easy) * argv;
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

    noncebytes = crypto_secretbox_xchacha20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_xchacha20poly1305_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, easy))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, easy) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, easy)));
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
LS_API_EXEC(crypto_secretbox_xchacha20poly1305, easy)
{
    LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, easy) * argv;
    LS_API_READ_ARGV(crypto_secretbox_xchacha20poly1305, easy);

    size_t macbytes = crypto_secretbox_xchacha20poly1305_macbytes();
    size_t clen = macbytes + argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_secretbox_xchacha20poly1305_easy(c, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_secretbox_xchacha20poly1305_open_easy/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox_xchacha20poly1305, open_easy) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char n[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
    const unsigned char k[crypto_secretbox_xchacha20poly1305_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_easy);

static int
LS_API_INIT(crypto_secretbox_xchacha20poly1305, open_easy)
{
    LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_easy) * argv;
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

    noncebytes = crypto_secretbox_xchacha20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_xchacha20poly1305_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_easy))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_easy) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_easy)));
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
LS_API_EXEC(crypto_secretbox_xchacha20poly1305, open_easy)
{
    LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_easy) * argv;
    LS_API_READ_ARGV(crypto_secretbox_xchacha20poly1305, open_easy);

    size_t macbytes = crypto_secretbox_xchacha20poly1305_macbytes();
    size_t mlen = argv->clen - macbytes;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_secretbox_xchacha20poly1305_open_easy(m, argv->c, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_secretbox_xchacha20poly1305_detached/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox_xchacha20poly1305, detached) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char n[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
    const unsigned char k[crypto_secretbox_xchacha20poly1305_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, detached);

static int
LS_API_INIT(crypto_secretbox_xchacha20poly1305, detached)
{
    LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, detached) * argv;
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

    noncebytes = crypto_secretbox_xchacha20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_xchacha20poly1305_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, detached)));
    argv->m = (const unsigned char *)(p);
    p += mlen;

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
LS_API_EXEC(crypto_secretbox_xchacha20poly1305, detached)
{
    LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, detached) * argv;
    LS_API_READ_ARGV(crypto_secretbox_xchacha20poly1305, detached);

    size_t macbytes = crypto_secretbox_xchacha20poly1305_macbytes();
    size_t clen = argv->mlen;
    unsigned char c[clen];
    unsigned char mac[macbytes];

    LS_SAFE_REPLY(crypto_secretbox_xchacha20poly1305_detached(c, mac, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(mac), macbytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(c, clen);
    (void)sodium_memzero(mac, macbytes);
}

/* crypto_secretbox_xchacha20poly1305_open_detached/4 */

typedef struct LS_API_F_ARGV(crypto_secretbox_xchacha20poly1305, open_detached) {
    const unsigned char *c;
    const unsigned char mac[crypto_secretbox_xchacha20poly1305_MACBYTES];
    unsigned long long clen;
    const unsigned char n[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
    const unsigned char k[crypto_secretbox_xchacha20poly1305_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_detached);

static int
LS_API_INIT(crypto_secretbox_xchacha20poly1305, open_detached)
{
    LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_detached) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long clen;
    size_t macbytes;
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

    macbytes = crypto_secretbox_xchacha20poly1305_macbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != macbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    noncebytes = crypto_secretbox_xchacha20poly1305_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_xchacha20poly1305_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_detached)));
    argv->c = (const unsigned char *)(p);
    p += clen;

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->mac), NULL) < 0) {
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
LS_API_EXEC(crypto_secretbox_xchacha20poly1305, open_detached)
{
    LS_API_F_ARGV_T(crypto_secretbox_xchacha20poly1305, open_detached) * argv;
    LS_API_READ_ARGV(crypto_secretbox_xchacha20poly1305, open_detached);

    size_t mlen = argv->clen;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_secretbox_xchacha20poly1305_open_detached(m, argv->c, argv->mac, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}
