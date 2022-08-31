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
static int LS_API_INIT(utils, sub);
static void LS_API_EXEC(utils, sub);
static int LS_API_INIT(utils, bin2hex);
static void LS_API_EXEC(utils, bin2hex);
static int LS_API_INIT(utils, hex2bin);
static void LS_API_EXEC(utils, hex2bin);
static void LS_API_EXEC(utils, base64_variants);
static int LS_API_INIT(utils, base64_encoded_len);
static void LS_API_EXEC(utils, base64_encoded_len);
static int LS_API_INIT(utils, bin2base64);
static void LS_API_EXEC(utils, bin2base64);
static int LS_API_INIT(utils, base642bin);
static void LS_API_EXEC(utils, base642bin);
static int LS_API_INIT(utils, pad);
static void LS_API_EXEC(utils, pad);
static int LS_API_INIT(utils, unpad);
static void LS_API_EXEC(utils, unpad);

libsodium_function_t libsodium_functions_utils[] = {LS_API_R_ARGV(utils, compare, 2),
                                                    LS_API_R_ARGV(utils, is_zero, 1),
                                                    LS_API_R_ARGV(utils, increment, 1),
                                                    LS_API_R_ARGV(utils, add, 2),
                                                    LS_API_R_ARGV(utils, sub, 2),
                                                    LS_API_R_ARGV(utils, bin2hex, 1),
                                                    LS_API_R_ARGV(utils, hex2bin, 2),
                                                    LS_API_R_ARG0(utils, base64_variants),
                                                    LS_API_R_ARGV(utils, base64_encoded_len, 2),
                                                    LS_API_R_ARGV(utils, bin2base64, 2),
                                                    LS_API_R_ARGV(utils, base642bin, 3),
                                                    LS_API_R_ARGV(utils, pad, 2),
                                                    LS_API_R_ARGV(utils, unpad, 2),
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

/* utils_sub/2 */

typedef struct LS_API_F_ARGV(utils, sub) {
    unsigned char *a;
    const unsigned char *b;
    size_t len;
} LS_API_F_ARGV_T(utils, sub);

static int
LS_API_INIT(utils, sub)
{
    LS_API_F_ARGV_T(utils, sub) * argv;
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

    x = (ErlDrvSizeT)(len + len + (sizeof(LS_API_F_ARGV_T(utils, sub))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, sub) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, sub)));
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
LS_API_EXEC(utils, sub)
{
    LS_API_F_ARGV_T(utils, sub) * argv;
    LS_API_READ_ARGV(utils, sub);

    (void)sodium_sub(argv->a, argv->b, argv->len);

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

/* utils_base64_variants/0 */

typedef struct libsodium_api_utils_base64_variant_s {
    const char *name;
    int variant;
    ErlDrvTermData am_name;
} libsodium_api_utils_base64_variant_t;

static libsodium_api_utils_base64_variant_t libsodium_api_utils_base64_variants_table[] = {
    {"original", sodium_base64_VARIANT_ORIGINAL},
    {"original_no_padding", sodium_base64_VARIANT_ORIGINAL_NO_PADDING},
    {"urlsafe", sodium_base64_VARIANT_URLSAFE},
    {"urlsafe_no_padding", sodium_base64_VARIANT_URLSAFE_NO_PADDING},
    {NULL}};

void
init_libsodium_api_utils_base64_variants(void)
{
    libsodium_api_utils_base64_variant_t *v = NULL;
    for (v = libsodium_api_utils_base64_variants_table; v->name != NULL; v++) {
        v->am_name = driver_mk_atom((char *)(v->name));
    }
}

static libsodium_api_utils_base64_variant_t *
get_libsodium_api_utils_base64_variant_by_name(const char *name)
{
    libsodium_api_utils_base64_variant_t *v = NULL;
    ErlDrvTermData am_name;
    (void)erl_drv_mutex_lock(libsodium_mutex);
    am_name = driver_mk_atom((char *)name);
    (void)erl_drv_mutex_unlock(libsodium_mutex);
    for (v = libsodium_api_utils_base64_variants_table; v->name != NULL; v++) {
        if (v->am_name == am_name) {
            return v;
        }
    }
    return NULL;
}

static libsodium_api_utils_base64_variant_t *
get_libsodium_api_utils_base64_variant_by_int(const int variant)
{
    libsodium_api_utils_base64_variant_t *v = NULL;
    for (v = libsodium_api_utils_base64_variants_table; v->name != NULL; v++) {
        if (v->variant == variant) {
            return v;
        }
    }
    return NULL;
}

static void
LS_API_EXEC(utils, base64_variants)
{
    libsodium_api_utils_base64_variant_t *v = NULL;
    size_t n_variants = 0;
    int i = 0;

    for (v = libsodium_api_utils_base64_variants_table; v->name != NULL; v++) {
        n_variants += 1;
    }

    ErlDrvTermData spec[(3 + (2 * n_variants) + 1 + 4)];

    spec[i++] = ERL_DRV_EXT2TERM;
    spec[i++] = (ErlDrvTermData)(request->tag.buff);
    spec[i++] = (ErlDrvTermData)(request->tag.index);
    for (v = libsodium_api_utils_base64_variants_table; v->name != NULL; v++) {
        spec[i++] = ERL_DRV_ATOM;
        spec[i++] = (ErlDrvTermData)(v->am_name);
    }
    spec[i++] = ERL_DRV_NIL;
    spec[i++] = ERL_DRV_LIST;
    spec[i++] = (ErlDrvTermData)(n_variants + 1);
    spec[i++] = ERL_DRV_TUPLE;
    spec[i++] = 2;

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* utils_base64_encoded_len/2 */

typedef struct LS_API_F_ARGV(utils, base64_encoded_len) {
    size_t bin_len;
    libsodium_api_utils_base64_variant_t *v;
} LS_API_F_ARGV_T(utils, base64_encoded_len);

static int
LS_API_INIT(utils, base64_encoded_len)
{
    LS_API_F_ARGV_T(utils, base64_encoded_len) * argv;
    int type;
    int type_length;
    ei_term term;
    size_t bin_len;
    libsodium_api_utils_base64_variant_t *v = NULL;
    ErlDrvSizeT x;
    void *p;

    if (ei_decode_ulong(buffer, index, (unsigned long *)(&bin_len)) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || (type != ERL_ATOM_EXT && type != ERL_SMALL_INTEGER_EXT)) {
        return -1;
    }
    if (ei_decode_ei_term(buffer, index, &term) < 0) {
        return -1;
    }
    if (type == ERL_ATOM_EXT) {
        v = get_libsodium_api_utils_base64_variant_by_name(term.value.atom_name);
    } else {
        v = get_libsodium_api_utils_base64_variant_by_int((int)(term.value.i_val));
    }
    if (v == NULL) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(utils, base64_encoded_len))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, base64_encoded_len) *)(p);
    argv->bin_len = bin_len;
    argv->v = v;

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, base64_encoded_len)
{
    LS_API_F_ARGV_T(utils, base64_encoded_len) * argv;
    LS_API_READ_ARGV(utils, base64_encoded_len);

    size_t encoded_len;

    encoded_len = sodium_base64_encoded_len(argv->bin_len, argv->v->variant);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(encoded_len), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* utils_bin2base64/2 */

typedef struct LS_API_F_ARGV(utils, bin2base64) {
    unsigned char *bin;
    size_t bin_len;
    libsodium_api_utils_base64_variant_t *v;
} LS_API_F_ARGV_T(utils, bin2base64);

static int
LS_API_INIT(utils, bin2base64)
{
    LS_API_F_ARGV_T(utils, bin2base64) * argv;
    int skip;
    int type;
    int type_length;
    ei_term term;
    size_t bin_len;
    int variant_type;
    libsodium_api_utils_base64_variant_t *v = NULL;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    bin_len = type_length;

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || (type != ERL_ATOM_EXT && type != ERL_SMALL_INTEGER_EXT)) {
        return -1;
    }

    variant_type = type;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(bin_len + (sizeof(LS_API_F_ARGV_T(utils, bin2base64))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, bin2base64) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, bin2base64)));
    argv->bin = (unsigned char *)(p);
    p += bin_len;

    if (ei_decode_binary(buffer, index, (void *)(argv->bin), (long *)&(argv->bin_len)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_ei_term(buffer, index, &term) < 0) {
        (void)driver_free(argv);
        return -1;
    }
    if (variant_type == ERL_ATOM_EXT) {
        v = get_libsodium_api_utils_base64_variant_by_name(term.value.atom_name);
    } else {
        v = get_libsodium_api_utils_base64_variant_by_int((int)(term.value.i_val));
    }
    if (v == NULL) {
        (void)driver_free(argv);
        return -1;
    }
    argv->v = v;

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, bin2base64)
{
    LS_API_F_ARGV_T(utils, bin2base64) * argv;
    LS_API_READ_ARGV(utils, bin2base64);

    size_t b64_maxlen = sodium_base64_encoded_len(argv->bin_len, argv->v->variant);
    char *b64 = (char *)(driver_alloc(b64_maxlen));

    if (b64 == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)sodium_bin2base64(b64, b64_maxlen, argv->bin, argv->bin_len, argv->v->variant);

    ErlDrvTermData spec[] = {LS_RES_TAG(request),      ERL_DRV_BUF2BINARY, (ErlDrvTermData)(b64),
                             strnlen(b64, b64_maxlen), ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* utils_base642bin/3 */

typedef struct LS_API_F_ARGV(utils, base642bin) {
    char *b64;
    size_t b64_len;
    char *ignore;
    libsodium_api_utils_base64_variant_t *v;
} LS_API_F_ARGV_T(utils, base642bin);

static int
LS_API_INIT(utils, base642bin)
{
    LS_API_F_ARGV_T(utils, base642bin) * argv;
    int skip;
    int type;
    int type_length;
    ei_term term;
    size_t b64_len;
    size_t ignore_len;
    int variant_type;
    libsodium_api_utils_base64_variant_t *v = NULL;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    b64_len = type_length;

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

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || (type != ERL_ATOM_EXT && type != ERL_SMALL_INTEGER_EXT)) {
        return -1;
    }

    variant_type = type;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(b64_len + ignore_len + (sizeof(LS_API_F_ARGV_T(utils, base642bin))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, base642bin) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, base642bin)));
    argv->b64 = (char *)(p);
    p += b64_len;
    if (ignore_len == 0) {
        argv->ignore = NULL;
    } else {
        argv->ignore = (char *)(p);
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->b64), (long *)&(argv->b64_len)) < 0) {
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
    } else {
        if (ei_skip_term(buffer, index) < 0) {
            (void)driver_free(argv);
            return -1;
        }
    }

    if (ei_decode_ei_term(buffer, index, &term) < 0) {
        (void)driver_free(argv);
        return -1;
    }
    if (variant_type == ERL_ATOM_EXT) {
        v = get_libsodium_api_utils_base64_variant_by_name(term.value.atom_name);
    } else {
        v = get_libsodium_api_utils_base64_variant_by_int((int)(term.value.i_val));
    }
    if (v == NULL) {
        (void)driver_free(argv);
        return -1;
    }
    argv->v = v;

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, base642bin)
{
    LS_API_F_ARGV_T(utils, base642bin) * argv;
    LS_API_READ_ARGV(utils, base642bin);

    size_t bin_maxlen = argv->b64_len;
    unsigned char *bin = NULL;
    size_t bin_len = 0;

    bin = (unsigned char *)(driver_alloc(bin_maxlen));

    if (bin == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    LS_SAFE_REPLY(sodium_base642bin(bin, bin_maxlen, argv->b64, argv->b64_len, argv->ignore, &bin_len, NULL, argv->v->variant),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(bin), bin_len, ERL_DRV_TUPLE, 2}), __FILE__,
                  __LINE__);

    if (bin_len > 0) {
        (void)sodium_memzero(bin, bin_len);
    }
    (void)driver_free((void *)bin);
}

/* utils_pad/2 */

typedef struct LS_API_F_ARGV(utils, pad) {
    unsigned char *unpadded_buf;
    size_t unpadded_buflen;
    size_t blocksize;
    size_t max_buflen;
} LS_API_F_ARGV_T(utils, pad);

static int
LS_API_INIT(utils, pad)
{
    LS_API_F_ARGV_T(utils, pad) * argv;
    int skip;
    int type;
    int type_length;
    size_t unpadded_buflen;
    size_t blocksize;
    size_t xpadlen;
    size_t max_buflen;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    unpadded_buflen = type_length;

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulonglong(buffer, &skip, (unsigned long long *)(&blocksize)) < 0) {
        return -1;
    }

    xpadlen = blocksize - 1U;
    if ((blocksize & (blocksize - 1U)) == 0U) {
        xpadlen -= unpadded_buflen & (blocksize - 1U);
    } else {
        xpadlen -= unpadded_buflen % blocksize;
    }

    if ((size_t)SIZE_MAX - unpadded_buflen <= xpadlen) {
        return -1;
    }

    max_buflen = unpadded_buflen + xpadlen + 1;

    x = (ErlDrvSizeT)(max_buflen + (sizeof(LS_API_F_ARGV_T(utils, pad))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, pad) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, pad)));
    argv->unpadded_buf = (unsigned char *)(p);
    p += max_buflen;

    if (ei_decode_binary(buffer, index, (void *)(argv->unpadded_buf), (long *)&(argv->unpadded_buflen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_ulonglong(buffer, index, (unsigned long long *)(&argv->blocksize)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    argv->max_buflen = max_buflen;

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, pad)
{
    LS_API_F_ARGV_T(utils, pad) * argv;
    LS_API_READ_ARGV(utils, pad);

    size_t padded_buflen = 0;
    unsigned char *buf = argv->unpadded_buf;

    LS_SAFE_REPLY(sodium_pad(&padded_buflen, buf, argv->unpadded_buflen, argv->blocksize, argv->max_buflen),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(buf), padded_buflen, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    if (padded_buflen > 0) {
        (void)sodium_memzero(buf, padded_buflen);
    }
}

/* utils_unpad/2 */

typedef struct LS_API_F_ARGV(utils, unpad) {
    unsigned char *padded_buf;
    size_t padded_buflen;
    size_t blocksize;
    size_t max_buflen;
} LS_API_F_ARGV_T(utils, unpad);

static int
LS_API_INIT(utils, unpad)
{
    LS_API_F_ARGV_T(utils, unpad) * argv;
    int skip;
    int type;
    int type_length;
    size_t padded_buflen;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    padded_buflen = type_length;

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(padded_buflen + (sizeof(LS_API_F_ARGV_T(utils, unpad))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(utils, unpad) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(utils, unpad)));
    argv->padded_buf = (unsigned char *)(p);
    p += padded_buflen;

    if (ei_decode_binary(buffer, index, (void *)(argv->padded_buf), (long *)&(argv->padded_buflen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_ulonglong(buffer, index, (unsigned long long *)(&argv->blocksize)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(utils, unpad)
{
    LS_API_F_ARGV_T(utils, unpad) * argv;
    LS_API_READ_ARGV(utils, unpad);

    size_t unpadded_buflen = 0;
    unsigned char *buf = argv->padded_buf;

    LS_SAFE_REPLY(sodium_unpad(&unpadded_buflen, buf, argv->padded_buflen, argv->blocksize),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(buf), unpadded_buflen, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    if (unpadded_buflen > 0) {
        (void)sodium_memzero(buf, unpadded_buflen);
    }
}
