// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_pwhash_scryptsalsa208sha256.h"

static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, bytes_min);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, bytes_max);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, passwd_min);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, passwd_max);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, saltbytes);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, strbytes);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, strprefix);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, opslimit_min);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, opslimit_max);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, memlimit_min);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, memlimit_max);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, opslimit_interactive);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, memlimit_interactive);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, opslimit_sensitive);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, memlimit_sensitive);
static int LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256);
static int LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, str);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, str);
static int LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, str_verify);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, str_verify);
static int LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, ll);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, ll);
static int LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash);
static void LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash);

libsodium_function_t libsodium_functions_crypto_pwhash_scryptsalsa208sha256[] = {
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, bytes_min),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, bytes_max),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, passwd_min),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, passwd_max),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, saltbytes),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, strbytes),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, strprefix),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, opslimit_min),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, opslimit_max),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, memlimit_min),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, memlimit_max),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, opslimit_interactive),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, memlimit_interactive),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, opslimit_sensitive),
    LS_API_R_ARG0(crypto_pwhash_scryptsalsa208sha256, memlimit_sensitive),
    LS_API_R_ARGV(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256, 5),
    LS_API_R_ARGV(crypto_pwhash_scryptsalsa208sha256, str, 3),
    LS_API_R_ARGV(crypto_pwhash_scryptsalsa208sha256, str_verify, 2),
    LS_API_R_ARGV(crypto_pwhash_scryptsalsa208sha256, ll, 6),
    LS_API_R_ARGV(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash, 3),
    {NULL}};

/* crypto_pwhash_scryptsalsa208sha256_bytes_min/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, bytes_min);

/* crypto_pwhash_scryptsalsa208sha256_bytes_max/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, bytes_max);

/* crypto_pwhash_scryptsalsa208sha256_passwd_min/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, passwd_min);

/* crypto_pwhash_scryptsalsa208sha256_passwd_max/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, passwd_max);

/* crypto_pwhash_scryptsalsa208sha256_saltbytes/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, saltbytes);

/* crypto_pwhash_scryptsalsa208sha256_strbytes/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, strbytes);

/* crypto_pwhash_scryptsalsa208sha256_strprefix/0 */

LS_API_GET_STR(crypto_pwhash_scryptsalsa208sha256, strprefix);

/* crypto_pwhash_scryptsalsa208sha256_opslimit_min/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, opslimit_min);

/* crypto_pwhash_scryptsalsa208sha256_opslimit_max/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, opslimit_max);

/* crypto_pwhash_scryptsalsa208sha256_memlimit_min/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, memlimit_min);

/* crypto_pwhash_scryptsalsa208sha256_memlimit_max/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, memlimit_max);

/* crypto_pwhash_scryptsalsa208sha256_opslimit_interactive/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, opslimit_interactive);

/* crypto_pwhash_scryptsalsa208sha256_memlimit_interactive/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, memlimit_interactive);

/* crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, opslimit_sensitive);

/* crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive/0 */

LS_API_GET_SIZE(crypto_pwhash_scryptsalsa208sha256, memlimit_sensitive);

/* crypto_pwhash_scryptsalsa208sha256_crypto_pwhash_scryptsalsa208sha256/5 */

typedef struct LS_API_F_ARGV(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256) {
    unsigned long long outlen;
    const char *passwd;
    unsigned long long passwdlen;
    const unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    unsigned long long opslimit;
    size_t memlimit;
} LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256);

static int
LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long outlen;
    unsigned long long passwdlen;
    size_t saltbytes;
    unsigned long long opslimit;
    size_t memlimit;
    ErlDrvSizeT x;
    void *p;

    if (ei_decode_ulong(buffer, index, (unsigned long *)&(outlen)) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    passwdlen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    saltbytes = crypto_pwhash_scryptsalsa208sha256_saltbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length != saltbytes) {
        return -1;
    }

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(opslimit)) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(memlimit)) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(passwdlen +
                      (sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256) *)(p);
    argv->outlen = outlen;
    argv->opslimit = opslimit;
    argv->memlimit = memlimit;
    p += (sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256)));
    argv->passwd = (const char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->passwd), (long *)&(argv->passwdlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->salt), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_skip_term(buffer, index) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_skip_term(buffer, index) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256) * argv;
    LS_API_READ_ARGV(crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256);

    unsigned char out[argv->outlen];

    LS_SAFE_REPLY(crypto_pwhash_scryptsalsa208sha256(out, argv->outlen, argv->passwd, argv->passwdlen, argv->salt, argv->opslimit,
                                                     argv->memlimit),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->outlen, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(out, argv->outlen);
}

/* crypto_pwhash_scryptsalsa208sha256_str/3 */

typedef struct LS_API_F_ARGV(crypto_pwhash_scryptsalsa208sha256, str) {
    const char *passwd;
    unsigned long long passwdlen;
    unsigned long long opslimit;
    size_t memlimit;
} LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str);

static int
LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, str)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long passwdlen;
    unsigned long long opslimit;
    size_t memlimit;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    passwdlen = (unsigned long long)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(opslimit)) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(memlimit)) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(passwdlen + (sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str) *)(p);
    argv->opslimit = opslimit;
    argv->memlimit = memlimit;
    p += (sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str)));
    argv->passwd = (const char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->passwd), (long *)&(argv->passwdlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_skip_term(buffer, index) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_skip_term(buffer, index) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, str)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str) * argv;
    LS_API_READ_ARGV(crypto_pwhash_scryptsalsa208sha256, str);

    char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES];

    LS_SAFE_REPLY(crypto_pwhash_scryptsalsa208sha256_str(out, argv->passwd, argv->passwdlen, argv->opslimit, argv->memlimit),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), strlen(out), ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(out, sizeof(out));
}

/* crypto_pwhash_scryptsalsa208sha256_str_verify/2 */

typedef struct LS_API_F_ARGV(crypto_pwhash_scryptsalsa208sha256, str_verify) {
    const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
    const char *passwd;
    unsigned long long passwdlen;
} LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_verify);

static int
LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, str_verify)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_verify) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long passwdlen;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT ||
        type_length > crypto_pwhash_scryptsalsa208sha256_STRBYTES) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    passwdlen = (unsigned long long)(type_length + 1);

    x = (ErlDrvSizeT)(passwdlen + (sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_verify))));
    p = (void *)(driver_alloc(x));
    (void)sodium_memzero(p, x);

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_verify) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_verify)));
    argv->passwd = (const char *)(p);

    if (ei_decode_binary(buffer, index, (void *)(argv->str), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->passwd), (long *)&(argv->passwdlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, str_verify)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_verify) * argv;
    LS_API_READ_ARGV(crypto_pwhash_scryptsalsa208sha256, str_verify);

    int r = crypto_pwhash_scryptsalsa208sha256_str_verify(argv->str, argv->passwd, argv->passwdlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_pwhash_scryptsalsa208sha256_ll/6 */

typedef struct LS_API_F_ARGV(crypto_pwhash_scryptsalsa208sha256, ll) {
    const uint8_t *passwd;
    size_t passwdlen;
    const uint8_t *salt;
    size_t saltlen;
    uint64_t N;
    uint32_t r;
    uint32_t p;
    size_t buflen;
} LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, ll);

static int
LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, ll)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, ll) * argv;
    int skip;
    int type;
    int type_length;
    size_t passwdlen;
    size_t saltlen;
    unsigned long param_N;
    unsigned long param_r;
    unsigned long param_p;
    size_t buflen;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    passwdlen = (size_t)(type_length);

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    saltlen = (size_t)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(param_N)) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(param_r)) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(param_p)) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(buflen)) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(passwdlen + saltlen + (sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, ll))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, ll) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, ll)));
    argv->passwd = (const uint8_t *)(p);
    p += passwdlen;
    argv->salt = (const uint8_t *)(p);
    argv->N = param_N;
    argv->r = param_r;
    argv->p = param_p;
    argv->buflen = buflen;

    if (ei_decode_binary(buffer, index, (void *)(argv->passwd), (long *)&(argv->passwdlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_decode_binary(buffer, index, (void *)(argv->salt), (long *)&(argv->saltlen)) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_skip_term(buffer, index) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_skip_term(buffer, index) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_skip_term(buffer, index) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    if (ei_skip_term(buffer, index) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, ll)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, ll) * argv;
    LS_API_READ_ARGV(crypto_pwhash_scryptsalsa208sha256, ll);

    uint8_t buf[argv->buflen];

    LS_SAFE_REPLY(crypto_pwhash_scryptsalsa208sha256_ll(argv->passwd, argv->passwdlen, argv->salt, argv->saltlen, argv->N, argv->r,
                                                        argv->p, buf, argv->buflen),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(buf), argv->buflen, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(buf, argv->buflen);
}

/* crypto_pwhash_scryptsalsa208sha256_str_needs_rehash/2 */

typedef struct LS_API_F_ARGV(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash) {
    const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
    unsigned long long opslimit;
    size_t memlimit;
} LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash);

static int
LS_API_INIT(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long opslimit;
    size_t memlimit;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT ||
        type_length > crypto_pwhash_scryptsalsa208sha256_STRBYTES) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(opslimit)) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(memlimit)) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(sizeof(LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash)));
    p = (void *)(driver_alloc(x));
    (void)sodium_memzero(p, x);

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash) *)(p);
    argv->opslimit = opslimit;
    argv->memlimit = memlimit;

    if (ei_decode_binary(buffer, index, (void *)(argv->str), NULL) < 0) {
        (void)driver_free(argv);
        return -1;
    }

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash)
{
    LS_API_F_ARGV_T(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash) * argv;
    LS_API_READ_ARGV(crypto_pwhash_scryptsalsa208sha256, str_needs_rehash);

    int r = crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(argv->str, argv->opslimit, argv->memlimit);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
