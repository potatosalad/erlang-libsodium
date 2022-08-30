// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_core_ristretto255.h"

static void LS_API_EXEC(crypto_core_ristretto255, bytes);
static void LS_API_EXEC(crypto_core_ristretto255, hashbytes);
static void LS_API_EXEC(crypto_core_ristretto255, scalarbytes);
static void LS_API_EXEC(crypto_core_ristretto255, nonreducedscalarbytes);
static int LS_API_INIT(crypto_core_ristretto255, is_valid_point);
static void LS_API_EXEC(crypto_core_ristretto255, is_valid_point);
static int LS_API_INIT(crypto_core_ristretto255, add);
static void LS_API_EXEC(crypto_core_ristretto255, add);
static int LS_API_INIT(crypto_core_ristretto255, sub);
static void LS_API_EXEC(crypto_core_ristretto255, sub);
static int LS_API_INIT(crypto_core_ristretto255, from_hash);
static void LS_API_EXEC(crypto_core_ristretto255, from_hash);
static void LS_API_EXEC(crypto_core_ristretto255, random);
static void LS_API_EXEC(crypto_core_ristretto255, scalar_random);
static int LS_API_INIT(crypto_core_ristretto255, scalar_invert);
static void LS_API_EXEC(crypto_core_ristretto255, scalar_invert);
static int LS_API_INIT(crypto_core_ristretto255, scalar_negate);
static void LS_API_EXEC(crypto_core_ristretto255, scalar_negate);
static int LS_API_INIT(crypto_core_ristretto255, scalar_complement);
static void LS_API_EXEC(crypto_core_ristretto255, scalar_complement);
static int LS_API_INIT(crypto_core_ristretto255, scalar_add);
static void LS_API_EXEC(crypto_core_ristretto255, scalar_add);
static int LS_API_INIT(crypto_core_ristretto255, scalar_sub);
static void LS_API_EXEC(crypto_core_ristretto255, scalar_sub);
static int LS_API_INIT(crypto_core_ristretto255, scalar_mul);
static void LS_API_EXEC(crypto_core_ristretto255, scalar_mul);
static int LS_API_INIT(crypto_core_ristretto255, scalar_reduce);
static void LS_API_EXEC(crypto_core_ristretto255, scalar_reduce);

libsodium_function_t libsodium_functions_crypto_core_ristretto255[] = {
    LS_API_R_ARG0(crypto_core_ristretto255, bytes),
    LS_API_R_ARG0(crypto_core_ristretto255, hashbytes),
    LS_API_R_ARG0(crypto_core_ristretto255, scalarbytes),
    LS_API_R_ARG0(crypto_core_ristretto255, nonreducedscalarbytes),
    LS_API_R_ARGV(crypto_core_ristretto255, is_valid_point, 1),
    LS_API_R_ARGV(crypto_core_ristretto255, add, 2),
    LS_API_R_ARGV(crypto_core_ristretto255, sub, 2),
    LS_API_R_ARGV(crypto_core_ristretto255, from_hash, 1),
    LS_API_R_ARG0(crypto_core_ristretto255, random),
    LS_API_R_ARG0(crypto_core_ristretto255, scalar_random),
    LS_API_R_ARGV(crypto_core_ristretto255, scalar_invert, 1),
    LS_API_R_ARGV(crypto_core_ristretto255, scalar_negate, 1),
    LS_API_R_ARGV(crypto_core_ristretto255, scalar_complement, 1),
    LS_API_R_ARGV(crypto_core_ristretto255, scalar_add, 2),
    LS_API_R_ARGV(crypto_core_ristretto255, scalar_sub, 2),
    LS_API_R_ARGV(crypto_core_ristretto255, scalar_mul, 2),
    LS_API_R_ARGV(crypto_core_ristretto255, scalar_reduce, 1),
    {NULL}};

/* crypto_core_ristretto255_bytes/0 */

LS_API_GET_SIZE(crypto_core_ristretto255, bytes);

/* crypto_core_ristretto255_hashbytes/0 */

LS_API_GET_SIZE(crypto_core_ristretto255, hashbytes);

/* crypto_core_ristretto255_scalarbytes/0 */

LS_API_GET_SIZE(crypto_core_ristretto255, scalarbytes);

/* crypto_core_ristretto255_nonreducedscalarbytes/0 */

LS_API_GET_SIZE(crypto_core_ristretto255, nonreducedscalarbytes);

/* crypto_core_ristretto255_is_valid_point/1 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, is_valid_point) {
    const unsigned char p[crypto_core_ristretto255_BYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, is_valid_point);

static int
LS_API_INIT(crypto_core_ristretto255, is_valid_point)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, is_valid_point) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_core_ristretto255_bytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != bytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, is_valid_point))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, is_valid_point) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, is_valid_point)));

    if (ei_decode_binary(buffer, index, (void *)(argv->p), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_ristretto255, is_valid_point)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, is_valid_point) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, is_valid_point);

    int r = crypto_core_ristretto255_is_valid_point(argv->p);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_core_ristretto255_add/2 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, add) {
    const unsigned char p[crypto_core_ristretto255_BYTES];
    const unsigned char q[crypto_core_ristretto255_BYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, add);

static int
LS_API_INIT(crypto_core_ristretto255, add)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, add) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_core_ristretto255_bytes();

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

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, add))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, add) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, add)));

    if (ei_decode_binary(buffer, index, (void *)(argv->p), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->q), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_ristretto255, add)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, add) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, add);

    unsigned char rp[crypto_core_ristretto255_BYTES];

    LS_SAFE_REPLY(crypto_core_ristretto255_add(rp, argv->p, argv->q),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(rp), crypto_core_ristretto255_BYTES,
                              ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(rp, crypto_core_ristretto255_BYTES);
}

/* crypto_core_ristretto255_sub/2 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, sub) {
    const unsigned char p[crypto_core_ristretto255_BYTES];
    const unsigned char q[crypto_core_ristretto255_BYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, sub);

static int
LS_API_INIT(crypto_core_ristretto255, sub)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, sub) * argv;
    int skip;
    int type;
    int type_length;
    size_t bytes;
    ErlDrvSizeT x;
    void *p;

    bytes = crypto_core_ristretto255_bytes();

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

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, sub))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, sub) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, sub)));

    if (ei_decode_binary(buffer, index, (void *)(argv->p), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->q), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_ristretto255, sub)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, sub) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, sub);

    unsigned char rp[crypto_core_ristretto255_BYTES];

    LS_SAFE_REPLY(crypto_core_ristretto255_sub(rp, argv->p, argv->q),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(rp), crypto_core_ristretto255_BYTES,
                              ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(rp, crypto_core_ristretto255_BYTES);
}

/* crypto_core_ristretto255_from_hash/1 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, from_hash) {
    const unsigned char h[crypto_core_ristretto255_HASHBYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, from_hash);

static int
LS_API_INIT(crypto_core_ristretto255, from_hash)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, from_hash) * argv;
    int skip;
    int type;
    int type_length;
    size_t hashbytes;
    ErlDrvSizeT x;
    void *p;

    hashbytes = crypto_core_ristretto255_hashbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != hashbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, from_hash))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, from_hash) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, from_hash)));

    if (ei_decode_binary(buffer, index, (void *)(argv->h), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_ristretto255, from_hash)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, from_hash) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, from_hash);

    unsigned char rp[crypto_core_ristretto255_BYTES];

    LS_SAFE_REPLY(crypto_core_ristretto255_from_hash(rp, argv->h),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(rp), crypto_core_ristretto255_BYTES,
                              ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(rp, crypto_core_ristretto255_BYTES);
}

/* crypto_core_ristretto255_random/0 */

static void
LS_API_EXEC(crypto_core_ristretto255, random)
{
    unsigned char p[crypto_core_ristretto255_BYTES];

    (void)crypto_core_ristretto255_random(p);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(p), crypto_core_ristretto255_BYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_core_ristretto255_scalar_random/0 */

static void
LS_API_EXEC(crypto_core_ristretto255, scalar_random)
{
    unsigned char r[crypto_core_ristretto255_SCALARBYTES];

    (void)crypto_core_ristretto255_scalar_random(r);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(r), crypto_core_ristretto255_SCALARBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_core_ristretto255_scalar_invert/1 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, scalar_invert) {
    const unsigned char s[crypto_core_ristretto255_SCALARBYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_invert);

static int
LS_API_INIT(crypto_core_ristretto255, scalar_invert)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_invert) * argv;
    int skip;
    int type;
    int type_length;
    size_t scalarbytes;
    ErlDrvSizeT x;
    void *p;

    scalarbytes = crypto_core_ristretto255_scalarbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != scalarbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_invert))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_invert) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_invert)));

    if (ei_decode_binary(buffer, index, (void *)(argv->s), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_ristretto255, scalar_invert)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_invert) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, scalar_invert);

    unsigned char recip[crypto_core_ristretto255_SCALARBYTES];

    LS_SAFE_REPLY(crypto_core_ristretto255_scalar_invert(recip, argv->s),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(recip),
                              crypto_core_ristretto255_SCALARBYTES, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(recip, crypto_core_ristretto255_SCALARBYTES);
}

/* crypto_core_ristretto255_scalar_negate/1 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, scalar_negate) {
    const unsigned char s[crypto_core_ristretto255_SCALARBYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_negate);

static int
LS_API_INIT(crypto_core_ristretto255, scalar_negate)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_negate) * argv;
    int skip;
    int type;
    int type_length;
    size_t scalarbytes;
    ErlDrvSizeT x;
    void *p;

    scalarbytes = crypto_core_ristretto255_scalarbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != scalarbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_negate))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_negate) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_negate)));

    if (ei_decode_binary(buffer, index, (void *)(argv->s), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_ristretto255, scalar_negate)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_negate) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, scalar_negate);

    unsigned char neg[crypto_core_ristretto255_SCALARBYTES];

    (void)crypto_core_ristretto255_scalar_negate(neg, argv->s);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(neg), crypto_core_ristretto255_SCALARBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_memzero(neg, crypto_core_ristretto255_SCALARBYTES);
}

/* crypto_core_ristretto255_scalar_complement/1 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, scalar_complement) {
    const unsigned char s[crypto_core_ristretto255_SCALARBYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_complement);

static int
LS_API_INIT(crypto_core_ristretto255, scalar_complement)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_complement) * argv;
    int skip;
    int type;
    int type_length;
    size_t scalarbytes;
    ErlDrvSizeT x;
    void *p;

    scalarbytes = crypto_core_ristretto255_scalarbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != scalarbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_complement))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_complement) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_complement)));

    if (ei_decode_binary(buffer, index, (void *)(argv->s), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_ristretto255, scalar_complement)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_complement) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, scalar_complement);

    unsigned char comp[crypto_core_ristretto255_SCALARBYTES];

    (void)crypto_core_ristretto255_scalar_complement(comp, argv->s);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(comp), crypto_core_ristretto255_SCALARBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_memzero(comp, crypto_core_ristretto255_SCALARBYTES);
}

/* crypto_core_ristretto255_scalar_add/2 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, scalar_add) {
    const unsigned char x[crypto_core_ristretto255_SCALARBYTES];
    const unsigned char y[crypto_core_ristretto255_SCALARBYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_add);

static int
LS_API_INIT(crypto_core_ristretto255, scalar_add)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_add) * argv;
    int skip;
    int type;
    int type_length;
    size_t scalarbytes;
    ErlDrvSizeT x;
    void *p;

    scalarbytes = crypto_core_ristretto255_scalarbytes();

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

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_add))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_add) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_add)));

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
LS_API_EXEC(crypto_core_ristretto255, scalar_add)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_add) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, scalar_add);

    unsigned char z[crypto_core_ristretto255_SCALARBYTES];

    (void)crypto_core_ristretto255_scalar_add(z, argv->x, argv->y);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(z), crypto_core_ristretto255_SCALARBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_memzero(z, crypto_core_ristretto255_SCALARBYTES);
}

/* crypto_core_ristretto255_scalar_sub/2 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, scalar_sub) {
    const unsigned char x[crypto_core_ristretto255_SCALARBYTES];
    const unsigned char y[crypto_core_ristretto255_SCALARBYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_sub);

static int
LS_API_INIT(crypto_core_ristretto255, scalar_sub)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_sub) * argv;
    int skip;
    int type;
    int type_length;
    size_t scalarbytes;
    ErlDrvSizeT x;
    void *p;

    scalarbytes = crypto_core_ristretto255_scalarbytes();

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

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_sub))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_sub) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_sub)));

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
LS_API_EXEC(crypto_core_ristretto255, scalar_sub)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_sub) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, scalar_sub);

    unsigned char z[crypto_core_ristretto255_SCALARBYTES];

    (void)crypto_core_ristretto255_scalar_sub(z, argv->x, argv->y);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(z), crypto_core_ristretto255_SCALARBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_memzero(z, crypto_core_ristretto255_SCALARBYTES);
}

/* crypto_core_ristretto255_scalar_mul/2 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, scalar_mul) {
    const unsigned char x[crypto_core_ristretto255_SCALARBYTES];
    const unsigned char y[crypto_core_ristretto255_SCALARBYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_mul);

static int
LS_API_INIT(crypto_core_ristretto255, scalar_mul)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_mul) * argv;
    int skip;
    int type;
    int type_length;
    size_t scalarbytes;
    ErlDrvSizeT x;
    void *p;

    scalarbytes = crypto_core_ristretto255_scalarbytes();

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

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_mul))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_mul) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_mul)));

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
LS_API_EXEC(crypto_core_ristretto255, scalar_mul)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_mul) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, scalar_mul);

    unsigned char z[crypto_core_ristretto255_SCALARBYTES];

    (void)crypto_core_ristretto255_scalar_mul(z, argv->x, argv->y);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(z), crypto_core_ristretto255_SCALARBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_memzero(z, crypto_core_ristretto255_SCALARBYTES);
}

/* crypto_core_ristretto255_scalar_reduce/1 */

typedef struct LS_API_F_ARGV(crypto_core_ristretto255, scalar_reduce) {
    const unsigned char s[crypto_core_ristretto255_NONREDUCEDSCALARBYTES];
} LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_reduce);

static int
LS_API_INIT(crypto_core_ristretto255, scalar_reduce)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_reduce) * argv;
    int skip;
    int type;
    int type_length;
    size_t nonreducedscalarbytes;
    ErlDrvSizeT x;
    void *p;

    nonreducedscalarbytes = crypto_core_ristretto255_nonreducedscalarbytes();

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != nonreducedscalarbytes) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)((sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_reduce))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_reduce) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_reduce)));

    if (ei_decode_binary(buffer, index, (void *)(argv->s), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_core_ristretto255, scalar_reduce)
{
    LS_API_F_ARGV_T(crypto_core_ristretto255, scalar_reduce) * argv;
    LS_API_READ_ARGV(crypto_core_ristretto255, scalar_reduce);

    unsigned char rs[crypto_core_ristretto255_SCALARBYTES];

    (void)crypto_core_ristretto255_scalar_reduce(rs, argv->s);

    ErlDrvTermData spec[] = {
        LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(rs), crypto_core_ristretto255_SCALARBYTES, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)sodium_memzero(rs, crypto_core_ristretto255_SCALARBYTES);
}
