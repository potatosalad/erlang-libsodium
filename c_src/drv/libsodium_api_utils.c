// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_utils.h"

static int LS_API_INIT(utils, compare);
static void LS_API_EXEC(utils, compare);
static int LS_API_INIT(utils, is_zero);
static void LS_API_EXEC(utils, is_zero);
static int LS_API_INIT(utils, increment);
static void LS_API_EXEC(utils, increment);
static int LS_API_INIT(utils, add);
static void LS_API_EXEC(utils, add);
static int LS_API_INIT(utils, bin2hex);
static void LS_API_EXEC(utils, bin2hex);
static int LS_API_INIT(utils, hex2bin);
static void LS_API_EXEC(utils, hex2bin);

libsodium_function_t libsodium_functions_utils[] = {LS_API_R_ARGV(utils, compare, 2),
                                                    LS_API_R_ARGV(utils, is_zero, 1),
                                                    LS_API_R_ARGV(utils, increment, 1),
                                                    LS_API_R_ARGV(utils, add, 2),
                                                    LS_API_R_ARGV(utils, bin2hex, 1),
                                                    LS_API_R_ARGV(utils, hex2bin, 2),
                                                    {NULL}};

/* utils_compare/2 */

typedef struct LS_API_F_ARGV(utils, compare) {
    const void *b1;
    const void *b2;
    size_t len;
} LS_API_F_ARGV_T(utils, compare);

static int
LS_API_INIT(utils, compare)
{
    LS_API_F_ARGV_T(utils, compare) * argv;
    int skip;
    int type;
    int type_length;
    size_t len;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    len = (size_t)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != len) {
        return -1;
    }

    x = (ErlDrvSizeT)(len + len + (sizeof(LS_API_F_ARGV_T(utils, compare))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, compare) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, compare)));
    argv->b1 = (const unsigned char *)(p);
    p += len;
    argv->b2 = (const unsigned char *)(p);
    argv->len = len;

    if (ei_decode_binary(buffer, index, (void *)(argv->b1), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->b2), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, compare)
{
    LS_API_F_ARGV_T(utils, compare) * argv;
    LS_API_READ_ARGV(utils, compare);
    int r;

    r = sodium_compare(argv->b1, argv->b2, argv->len);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* utils_is_zero/1 */

typedef struct LS_API_F_ARGV(utils, is_zero) {
    const unsigned char *n;
    size_t nlen;
} LS_API_F_ARGV_T(utils, is_zero);

static int
LS_API_INIT(utils, is_zero)
{
    LS_API_F_ARGV_T(utils, is_zero) * argv;
    int type;
    int type_length;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    x = (ErlDrvSizeT)(type_length + (sizeof(LS_API_F_ARGV_T(utils, is_zero))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, is_zero) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, is_zero)));
    argv->n = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->n), (long *)&(argv->nlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, is_zero)
{
    LS_API_F_ARGV_T(utils, is_zero) * argv;
    LS_API_READ_ARGV(utils, is_zero);
    int r;

    r = sodium_is_zero(argv->n, argv->nlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* utils_increment/1 */

typedef struct LS_API_F_ARGV(utils, increment) {
    unsigned char *n;
    size_t nlen;
} LS_API_F_ARGV_T(utils, increment);

static int
LS_API_INIT(utils, increment)
{
    LS_API_F_ARGV_T(utils, increment) * argv;
    int type;
    int type_length;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    x = (ErlDrvSizeT)(type_length + (sizeof(LS_API_F_ARGV_T(utils, increment))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, increment) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, increment)));
    argv->n = (unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->n), (long *)&(argv->nlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, increment)
{
    LS_API_F_ARGV_T(utils, increment) * argv;
    LS_API_READ_ARGV(utils, increment);

    (void)sodium_increment(argv->n, argv->nlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(argv->n), argv->nlen, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* utils_add/2 */

typedef struct LS_API_F_ARGV(utils, add) {
    unsigned char *a;
    const unsigned char *b;
    size_t len;
} LS_API_F_ARGV_T(utils, add);

static int
LS_API_INIT(utils, add)
{
    LS_API_F_ARGV_T(utils, add) * argv;
    int skip;
    int type;
    int type_length;
    size_t len;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    len = (size_t)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != len) {
        return -1;
    }

    x = (ErlDrvSizeT)(len + len + (sizeof(LS_API_F_ARGV_T(utils, add))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, add) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, add)));
    argv->a = (unsigned char *)(p);
    p += len;
    argv->b = (const unsigned char *)(p);
    argv->len = len;

    if (ei_decode_binary(buffer, index, (void *)(argv->a), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->b), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, add)
{
    LS_API_F_ARGV_T(utils, add) * argv;
    LS_API_READ_ARGV(utils, add);

    (void)sodium_add(argv->a, argv->b, argv->len);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(argv->a), argv->len, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* utils_bin2hex/1 */

typedef struct LS_API_F_ARGV(utils, bin2hex) {
    const unsigned char *bin;
    size_t bin_len;
} LS_API_F_ARGV_T(utils, bin2hex);

static int
LS_API_INIT(utils, bin2hex)
{
    LS_API_F_ARGV_T(utils, bin2hex) * argv;
    int type;
    int type_length;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    x = (ErlDrvSizeT)(type_length + (sizeof(LS_API_F_ARGV_T(utils, bin2hex))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, bin2hex) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, bin2hex)));
    argv->bin = (const unsigned char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->bin), (long *)&(argv->bin_len)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, bin2hex)
{
    LS_API_F_ARGV_T(utils, bin2hex) * argv;
    LS_API_READ_ARGV(utils, bin2hex);

    size_t hex_maxlen = (argv->bin_len * 2) + 1;
    char hex[hex_maxlen];
    char *hexp;

    hexp = sodium_bin2hex(hex, hex_maxlen, argv->bin, argv->bin_len);

    if (hexp == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(hex), strlen(hex), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_memzero(hex, strlen(hex));
}

/* utils_hex2bin/2 */

typedef struct LS_API_F_ARGV(utils, hex2bin) {
    const char *hex;
    const size_t hex_len;
    const char *ignore;
} LS_API_F_ARGV_T(utils, hex2bin);

static int
LS_API_INIT(utils, hex2bin)
{
    LS_API_F_ARGV_T(utils, hex2bin) * argv;
    int skip;
    int type;
    int type_length;
    size_t hex_len;
    size_t ignore_len;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    hex_len = (size_t)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    ignore_len = (size_t)(type_length);

    if (ignore_len > 0) {
        ignore_len += 1;
    }

    x = (ErlDrvSizeT)(hex_len + ignore_len + (sizeof(LS_API_F_ARGV_T(utils, hex2bin))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, hex2bin) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, hex2bin)));
    argv->hex = (const char *)(p);
    p += hex_len;
    if (ignore_len == 0) {
        argv->ignore = NULL;
    } else {
        argv->ignore = (const char *)(p);
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->hex), (long *)&(argv->hex_len)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ignore_len > 0) {
        if (ei_decode_binary(buffer, index, (void *)(argv->ignore), (long *)&(ignore_len)) < 0) {
            (void)driver_free(argv);
            return -1;
        }
        char *c = (char *)(p + ignore_len);
        *c = '\0';
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, hex2bin)
{
    LS_API_F_ARGV_T(utils, hex2bin) * argv;
    LS_API_READ_ARGV(utils, hex2bin);

    size_t bin_maxlen = argv->hex_len;
    unsigned char bin[bin_maxlen];
    size_t bin_len = 0;

    LS_SAFE_REPLY(sodium_hex2bin(bin, bin_maxlen, argv->hex, argv->hex_len, argv->ignore, &bin_len, NULL),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(bin), bin_len, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    if (bin_len > 0) {
        (void)sodium_memzero(bin, bin_len);
    }
}
