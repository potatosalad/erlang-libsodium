// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_secretbox.h"

static void LS_API_EXEC(crypto_secretbox, keybytes);
static void LS_API_EXEC(crypto_secretbox, noncebytes);
static void LS_API_EXEC(crypto_secretbox, macbytes);
static void LS_API_EXEC(crypto_secretbox, primitive);
static void LS_API_EXEC(crypto_secretbox, messagebytes_max);
static int LS_API_INIT(crypto_secretbox, easy);
static void LS_API_EXEC(crypto_secretbox, easy);
static int LS_API_INIT(crypto_secretbox, open_easy);
static void LS_API_EXEC(crypto_secretbox, open_easy);
static int LS_API_INIT(crypto_secretbox, detached);
static void LS_API_EXEC(crypto_secretbox, detached);
static int LS_API_INIT(crypto_secretbox, open_detached);
static void LS_API_EXEC(crypto_secretbox, open_detached);
static void LS_API_EXEC(crypto_secretbox, keygen);
static void LS_API_EXEC(crypto_secretbox, zerobytes);
static void LS_API_EXEC(crypto_secretbox, boxzerobytes);
static int LS_API_INIT(crypto_secretbox, crypto_secretbox);
static void LS_API_EXEC(crypto_secretbox, crypto_secretbox);
static int LS_API_INIT(crypto_secretbox, open);
static void LS_API_EXEC(crypto_secretbox, open);

libsodium_function_t libsodium_functions_crypto_secretbox[] = {LS_API_R_ARG0(crypto_secretbox, keybytes),
                                                               LS_API_R_ARG0(crypto_secretbox, noncebytes),
                                                               LS_API_R_ARG0(crypto_secretbox, macbytes),
                                                               LS_API_R_ARG0(crypto_secretbox, primitive),
                                                               LS_API_R_ARG0(crypto_secretbox, messagebytes_max),
                                                               LS_API_R_ARGV(crypto_secretbox, easy, 3),
                                                               LS_API_R_ARGV(crypto_secretbox, open_easy, 3),
                                                               LS_API_R_ARGV(crypto_secretbox, detached, 3),
                                                               LS_API_R_ARGV(crypto_secretbox, open_detached, 4),
                                                               LS_API_R_ARG0(crypto_secretbox, keygen),
                                                               LS_API_R_ARG0(crypto_secretbox, zerobytes),
                                                               LS_API_R_ARG0(crypto_secretbox, boxzerobytes),
                                                               LS_API_R_ARGV(crypto_secretbox, crypto_secretbox, 3),
                                                               LS_API_R_ARGV(crypto_secretbox, open, 3),
                                                               {NULL}};

/* crypto_secretbox_keybytes/0 */

LS_API_GET_SIZE(crypto_secretbox, keybytes);

/* crypto_secretbox_noncebytes/0 */

LS_API_GET_SIZE(crypto_secretbox, noncebytes);

/* crypto_secretbox_macbytes/0 */

LS_API_GET_SIZE(crypto_secretbox, macbytes);

/* crypto_secretbox_primitive/0 */

LS_API_GET_ATOM(crypto_secretbox, primitive);

/* crypto_secretbox_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_secretbox, messagebytes_max);

/* crypto_secretbox_easy/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox, easy) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char n[crypto_secretbox_NONCEBYTES];
    const unsigned char k[crypto_secretbox_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox, easy);

SODIUM_EXPORT
int crypto_secretbox_easy(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n,
                          const unsigned char *k) __attribute__((nonnull(1, 4, 5)));

static int
LS_API_INIT(crypto_secretbox, easy)
{
    LS_API_F_ARGV_T(crypto_secretbox, easy) * argv;
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

    noncebytes = crypto_secretbox_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox, easy))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox, easy) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox, easy)));
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
LS_API_EXEC(crypto_secretbox, easy)
{
    LS_API_F_ARGV_T(crypto_secretbox, easy) * argv;
    LS_API_READ_ARGV(crypto_secretbox, easy);

    size_t macbytes = crypto_secretbox_macbytes();
    size_t clen = macbytes + argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_secretbox_easy(c, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_secretbox_open_easy/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox, open_easy) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char n[crypto_secretbox_NONCEBYTES];
    const unsigned char k[crypto_secretbox_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox, open_easy);

static int
LS_API_INIT(crypto_secretbox, open_easy)
{
    LS_API_F_ARGV_T(crypto_secretbox, open_easy) * argv;
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

    noncebytes = crypto_secretbox_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox, open_easy))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox, open_easy) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox, open_easy)));
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
LS_API_EXEC(crypto_secretbox, open_easy)
{
    LS_API_F_ARGV_T(crypto_secretbox, open_easy) * argv;
    LS_API_READ_ARGV(crypto_secretbox, open_easy);

    size_t macbytes = crypto_secretbox_macbytes();
    size_t mlen = argv->clen - macbytes;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_secretbox_open_easy(m, argv->c, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_secretbox_detached/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox, detached) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char n[crypto_secretbox_NONCEBYTES];
    const unsigned char k[crypto_secretbox_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox, detached);

static int
LS_API_INIT(crypto_secretbox, detached)
{
    LS_API_F_ARGV_T(crypto_secretbox, detached) * argv;
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

    noncebytes = crypto_secretbox_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox, detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox, detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox, detached)));
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
LS_API_EXEC(crypto_secretbox, detached)
{
    LS_API_F_ARGV_T(crypto_secretbox, detached) * argv;
    LS_API_READ_ARGV(crypto_secretbox, detached);

    size_t macbytes = crypto_secretbox_macbytes();
    size_t clen = argv->mlen;
    unsigned char c[clen];
    unsigned char mac[macbytes];

    LS_SAFE_REPLY(crypto_secretbox_detached(c, mac, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_BUF2BINARY,
                              (ErlDrvTermData)(mac), macbytes, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(c, clen);
    (void)sodium_memzero(mac, macbytes);
}

/* crypto_secretbox_open_detached/4 */

typedef struct LS_API_F_ARGV(crypto_secretbox, open_detached) {
    const unsigned char *c;
    const unsigned char mac[crypto_secretbox_MACBYTES];
    unsigned long long clen;
    const unsigned char n[crypto_secretbox_NONCEBYTES];
    const unsigned char k[crypto_secretbox_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox, open_detached);

static int
LS_API_INIT(crypto_secretbox, open_detached)
{
    LS_API_F_ARGV_T(crypto_secretbox, open_detached) * argv;
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

    macbytes = crypto_secretbox_macbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != macbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    noncebytes = crypto_secretbox_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox, open_detached))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox, open_detached) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox, open_detached)));
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
LS_API_EXEC(crypto_secretbox, open_detached)
{
    LS_API_F_ARGV_T(crypto_secretbox, open_detached) * argv;
    LS_API_READ_ARGV(crypto_secretbox, open_detached);

    size_t mlen = argv->clen;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_secretbox_open_detached(m, argv->c, argv->mac, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}

/* crypto_secretbox_keygen/0 */

static void
LS_API_EXEC(crypto_secretbox, keygen)
{
    unsigned char k[crypto_secretbox_KEYBYTES];

    (void)crypto_secretbox_keygen(k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request),       ERL_DRV_BUF2BINARY, (ErlDrvTermData)(k),
                             crypto_secretbox_KEYBYTES, ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_secretbox_zerobytes/0 */

LS_API_GET_SIZE(crypto_secretbox, zerobytes);

/* crypto_secretbox_boxzerobytes/0 */

LS_API_GET_SIZE(crypto_secretbox, boxzerobytes);

/* crypto_secretbox_crypto_secretbox/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox, crypto_secretbox) {
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char n[crypto_secretbox_NONCEBYTES];
    const unsigned char k[crypto_secretbox_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox, crypto_secretbox);

SODIUM_EXPORT
int crypto_secretbox_crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n,
                                      const unsigned char *k) __attribute__((nonnull(1, 4, 5)));

static int
LS_API_INIT(crypto_secretbox, crypto_secretbox)
{
    LS_API_F_ARGV_T(crypto_secretbox, crypto_secretbox) * argv;
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

    noncebytes = crypto_secretbox_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(mlen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox, crypto_secretbox))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox, crypto_secretbox) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox, crypto_secretbox)));
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
LS_API_EXEC(crypto_secretbox, crypto_secretbox)
{
    LS_API_F_ARGV_T(crypto_secretbox, crypto_secretbox) * argv;
    LS_API_READ_ARGV(crypto_secretbox, crypto_secretbox);

    size_t macbytes = crypto_secretbox_macbytes();
    size_t clen = macbytes + argv->mlen;
    unsigned char c[clen];

    LS_SAFE_REPLY(crypto_secretbox(c, argv->m, argv->mlen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(c, clen);
}

/* crypto_secretbox_open/3 */

typedef struct LS_API_F_ARGV(crypto_secretbox, open) {
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char n[crypto_secretbox_NONCEBYTES];
    const unsigned char k[crypto_secretbox_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretbox, open);

static int
LS_API_INIT(crypto_secretbox, open)
{
    LS_API_F_ARGV_T(crypto_secretbox, open) * argv;
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

    noncebytes = crypto_secretbox_noncebytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != noncebytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretbox_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(clen + (sizeof(LS_API_F_ARGV_T(crypto_secretbox, open))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretbox, open) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretbox, open)));
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
LS_API_EXEC(crypto_secretbox, open)
{
    LS_API_F_ARGV_T(crypto_secretbox, open) * argv;
    LS_API_READ_ARGV(crypto_secretbox, open);

    size_t macbytes = crypto_secretbox_macbytes();
    size_t mlen = argv->clen - macbytes;
    unsigned char m[mlen];

    LS_SAFE_REPLY(crypto_secretbox_open(m, argv->c, argv->clen, argv->n, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    (void)sodium_memzero(m, mlen);
}
