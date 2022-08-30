// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_secretstream_xchacha20poly1305.h"

static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, abytes);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, headerbytes);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, keybytes);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, messagebytes_max);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, tag_message);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, tag_push);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, tag_rekey);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, tag_final);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, statebytes);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, keygen);
static int LS_API_INIT(crypto_secretstream_xchacha20poly1305, init_push);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, init_push);
static int LS_API_INIT(crypto_secretstream_xchacha20poly1305, push);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, push);
static int LS_API_INIT(crypto_secretstream_xchacha20poly1305, init_pull);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, init_pull);
static int LS_API_INIT(crypto_secretstream_xchacha20poly1305, pull);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, pull);
static int LS_API_INIT(crypto_secretstream_xchacha20poly1305, rekey);
static void LS_API_EXEC(crypto_secretstream_xchacha20poly1305, rekey);

libsodium_function_t libsodium_functions_crypto_secretstream_xchacha20poly1305[] = {
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, abytes),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, headerbytes),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, keybytes),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, messagebytes_max),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, tag_message),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, tag_push),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, tag_rekey),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, tag_final),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, statebytes),
    LS_API_R_ARG0(crypto_secretstream_xchacha20poly1305, keygen),
    LS_API_R_ARGV(crypto_secretstream_xchacha20poly1305, init_push, 1),
    LS_API_R_ARGV(crypto_secretstream_xchacha20poly1305, push, 4),
    LS_API_R_ARGV(crypto_secretstream_xchacha20poly1305, init_pull, 2),
    LS_API_R_ARGV(crypto_secretstream_xchacha20poly1305, pull, 3),
    LS_API_R_ARGV(crypto_secretstream_xchacha20poly1305, rekey, 1),
    {NULL}};

/* crypto_secretstream_xchacha20poly1305_abytes/0 */

LS_API_GET_SIZE(crypto_secretstream_xchacha20poly1305, abytes);

/* crypto_secretstream_xchacha20poly1305_headerbytes/0 */

LS_API_GET_SIZE(crypto_secretstream_xchacha20poly1305, headerbytes);

/* crypto_secretstream_xchacha20poly1305_keybytes/0 */

LS_API_GET_SIZE(crypto_secretstream_xchacha20poly1305, keybytes);

/* crypto_secretstream_xchacha20poly1305_messagebytes_max/0 */

LS_API_GET_SIZE(crypto_secretstream_xchacha20poly1305, messagebytes_max);

/* crypto_secretstream_xchacha20poly1305_tag_message/0 */

LS_API_GET_SINT(crypto_secretstream_xchacha20poly1305, tag_message);

/* crypto_secretstream_xchacha20poly1305_tag_push/0 */

LS_API_GET_SINT(crypto_secretstream_xchacha20poly1305, tag_push);

/* crypto_secretstream_xchacha20poly1305_tag_rekey/0 */

LS_API_GET_SINT(crypto_secretstream_xchacha20poly1305, tag_rekey);

/* crypto_secretstream_xchacha20poly1305_tag_final/0 */

LS_API_GET_SINT(crypto_secretstream_xchacha20poly1305, tag_final);

/* crypto_secretstream_xchacha20poly1305_statebytes/0 */

LS_API_GET_SIZE(crypto_secretstream_xchacha20poly1305, statebytes);

/* crypto_secretstream_xchacha20poly1305_keygen/0 */

static void
LS_API_EXEC(crypto_secretstream_xchacha20poly1305, keygen)
{
    unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    (void)crypto_secretstream_xchacha20poly1305_keygen(k);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY,
                             (ErlDrvTermData)(k), crypto_secretstream_xchacha20poly1305_KEYBYTES,
                             ERL_DRV_TUPLE,       2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_secretstream_xchacha20poly1305_init_push/1 */

typedef struct LS_API_F_ARGV(crypto_secretstream_xchacha20poly1305, init_push) {
    const unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_push);

static int
LS_API_INIT(crypto_secretstream_xchacha20poly1305, init_push)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_push) * argv;
    int skip;
    int type;
    int type_length;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    keybytes = crypto_secretstream_xchacha20poly1305_keybytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_push))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_push) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_push)));

    if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_secretstream_xchacha20poly1305, init_push)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_push) * argv;
    LS_API_READ_ARGV(crypto_secretstream_xchacha20poly1305, init_push);
    size_t statebytes;
    crypto_secretstream_xchacha20poly1305_state *state;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    statebytes = crypto_secretstream_xchacha20poly1305_statebytes();

    state = (crypto_secretstream_xchacha20poly1305_state *)(sodium_malloc(statebytes));

    if (state == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(crypto_secretstream_xchacha20poly1305_init_push(state, header, argv->k),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state), statebytes,
                              ERL_DRV_BUF2BINARY, (ErlDrvTermData)(header), crypto_secretstream_xchacha20poly1305_HEADERBYTES,
                              ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(header, crypto_secretstream_xchacha20poly1305_HEADERBYTES);
    (void)sodium_free(state);
}

/* crypto_secretstream_xchacha20poly1305_push/4 */

typedef struct LS_API_F_ARGV(crypto_secretstream_xchacha20poly1305, push) {
    crypto_secretstream_xchacha20poly1305_state *state;
    const unsigned char *m;
    unsigned long long mlen;
    const unsigned char *ad;
    unsigned long long adlen;
    unsigned char tag;
} LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, push);

static int
LS_API_INIT(crypto_secretstream_xchacha20poly1305, push)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, push) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    unsigned long long mlen;
    unsigned long long adlen;
    unsigned char tag;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_secretstream_xchacha20poly1305_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    mlen = type_length;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    adlen = type_length;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_char(buffer, &skip, (char *)(&tag)) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + mlen + adlen + (sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, push))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, push) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, push)));
    argv->state = (crypto_secretstream_xchacha20poly1305_state *)(p);
    p += statebytes;
    argv->m = (const unsigned char *)(p);
    p += mlen;
    argv->ad = (const unsigned char *)(p);
    p += adlen;

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->ad), (long *)&(argv->adlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    argv->tag = tag;

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_secretstream_xchacha20poly1305, push)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, push) * argv;
    LS_API_READ_ARGV(crypto_secretstream_xchacha20poly1305, push);
    size_t statebytes;
    unsigned char *c = NULL;
    unsigned long long clen = argv->mlen + crypto_secretstream_xchacha20poly1305_abytes();

    statebytes = crypto_secretstream_xchacha20poly1305_statebytes();
    c = (unsigned char *)(driver_alloc((ErlDrvSizeT)(clen)));

    if (c == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(
        crypto_secretstream_xchacha20poly1305_push(argv->state, c, &clen, argv->m, argv->mlen, argv->ad, argv->adlen, argv->tag),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state), statebytes, ERL_DRV_BUF2BINARY,
                    (ErlDrvTermData)(c), clen, ERL_DRV_TUPLE, 2, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(c, clen);
    (void)driver_free(c);
}

/* crypto_secretstream_xchacha20poly1305_init_pull/2 */

typedef struct LS_API_F_ARGV(crypto_secretstream_xchacha20poly1305, init_pull) {
    const unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    const unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES];
} LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_pull);

static int
LS_API_INIT(crypto_secretstream_xchacha20poly1305, init_pull)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_pull) * argv;
    int skip;
    int type;
    int type_length;
    size_t headerbytes;
    size_t keybytes;
    ErlDrvSizeT x;
    void *p;

    headerbytes = crypto_secretstream_xchacha20poly1305_headerbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != headerbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    keybytes = crypto_secretstream_xchacha20poly1305_keybytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != keybytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_pull))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_pull) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_pull)));

    if (ei_decode_binary(buffer, index, (void *)(argv->header), NULL) < 0) {
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
LS_API_EXEC(crypto_secretstream_xchacha20poly1305, init_pull)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, init_pull) * argv;
    LS_API_READ_ARGV(crypto_secretstream_xchacha20poly1305, init_pull);
    size_t statebytes;
    crypto_secretstream_xchacha20poly1305_state *state;

    statebytes = crypto_secretstream_xchacha20poly1305_statebytes();

    state = (crypto_secretstream_xchacha20poly1305_state *)(sodium_malloc(statebytes));

    if (state == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(
        crypto_secretstream_xchacha20poly1305_init_pull(state, argv->header, argv->k),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(state), statebytes, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_free(state);
}

/* crypto_secretstream_xchacha20poly1305_pull/3 */

typedef struct LS_API_F_ARGV(crypto_secretstream_xchacha20poly1305, pull) {
    crypto_secretstream_xchacha20poly1305_state *state;
    const unsigned char *c;
    unsigned long long clen;
    const unsigned char *ad;
    unsigned long long adlen;
} LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, pull);

static int
LS_API_INIT(crypto_secretstream_xchacha20poly1305, pull)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, pull) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    size_t abytes;
    unsigned long long clen;
    unsigned long long adlen;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_secretstream_xchacha20poly1305_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    abytes = crypto_secretstream_xchacha20poly1305_abytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length < abytes) {
        return -1;
    }

    clen = type_length;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    adlen = type_length;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + clen + adlen + (sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, pull))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, pull) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, pull)));
    argv->state = (crypto_secretstream_xchacha20poly1305_state *)(p);
    p += statebytes;
    argv->c = (const unsigned char *)(p);
    p += clen;
    argv->ad = (const unsigned char *)(p);
    p += adlen;

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->ad), (long *)&(argv->adlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_secretstream_xchacha20poly1305, pull)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, pull) * argv;
    LS_API_READ_ARGV(crypto_secretstream_xchacha20poly1305, pull);
    size_t statebytes;
    unsigned char *m = NULL;
    unsigned long long mlen = argv->clen - crypto_secretstream_xchacha20poly1305_abytes();
    unsigned char tag;

    statebytes = crypto_secretstream_xchacha20poly1305_statebytes();
    m = (unsigned char *)(driver_alloc((ErlDrvSizeT)(mlen)));

    if (m == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(
        crypto_secretstream_xchacha20poly1305_pull(argv->state, m, &mlen, &tag, argv->c, argv->clen, argv->ad, argv->adlen),
        LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state), statebytes, ERL_DRV_BUF2BINARY,
                    (ErlDrvTermData)(m), mlen, ERL_DRV_UINT, (ErlDrvUInt)(tag), ERL_DRV_TUPLE, 3, ERL_DRV_TUPLE, 2}),
        __FILE__, __LINE__);

    (void)sodium_memzero(m, mlen);
    (void)driver_free(m);
}

/* crypto_secretstream_xchacha20poly1305_rekey/1 */

typedef struct LS_API_F_ARGV(crypto_secretstream_xchacha20poly1305, rekey) {
    crypto_secretstream_xchacha20poly1305_state *state;
} LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, rekey);

static int
LS_API_INIT(crypto_secretstream_xchacha20poly1305, rekey)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, rekey) * argv;
    int skip;
    int type;
    int type_length;
    size_t statebytes;
    ErlDrvSizeT x;
    void *p;

    statebytes = crypto_secretstream_xchacha20poly1305_statebytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != statebytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(statebytes + (sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, rekey))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, rekey) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, rekey)));
    argv->state = (crypto_secretstream_xchacha20poly1305_state *)(p);
    p += statebytes;

    if (ei_decode_binary(buffer, index, (void *)(argv->state), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_secretstream_xchacha20poly1305, rekey)
{
    LS_API_F_ARGV_T(crypto_secretstream_xchacha20poly1305, rekey) * argv;
    LS_API_READ_ARGV(crypto_secretstream_xchacha20poly1305, rekey);
    size_t statebytes;

    statebytes = crypto_secretstream_xchacha20poly1305_statebytes();

    (void)crypto_secretstream_xchacha20poly1305_rekey(argv->state);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(char *)(argv->state),
                             statebytes,          ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
