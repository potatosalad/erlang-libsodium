// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_crypto_pwhash_argon2i.h"

static void LS_API_EXEC(crypto_pwhash_argon2i, alg_argon2i13);
static void LS_API_EXEC(crypto_pwhash_argon2i, bytes_min);
static void LS_API_EXEC(crypto_pwhash_argon2i, bytes_max);
static void LS_API_EXEC(crypto_pwhash_argon2i, passwd_min);
static void LS_API_EXEC(crypto_pwhash_argon2i, passwd_max);
static void LS_API_EXEC(crypto_pwhash_argon2i, saltbytes);
static void LS_API_EXEC(crypto_pwhash_argon2i, strbytes);
static void LS_API_EXEC(crypto_pwhash_argon2i, strprefix);
static void LS_API_EXEC(crypto_pwhash_argon2i, opslimit_min);
static void LS_API_EXEC(crypto_pwhash_argon2i, opslimit_max);
static void LS_API_EXEC(crypto_pwhash_argon2i, memlimit_min);
static void LS_API_EXEC(crypto_pwhash_argon2i, memlimit_max);
static void LS_API_EXEC(crypto_pwhash_argon2i, opslimit_interactive);
static void LS_API_EXEC(crypto_pwhash_argon2i, memlimit_interactive);
static void LS_API_EXEC(crypto_pwhash_argon2i, opslimit_moderate);
static void LS_API_EXEC(crypto_pwhash_argon2i, memlimit_moderate);
static void LS_API_EXEC(crypto_pwhash_argon2i, opslimit_sensitive);
static void LS_API_EXEC(crypto_pwhash_argon2i, memlimit_sensitive);
static int LS_API_INIT(crypto_pwhash_argon2i, crypto_pwhash_argon2i);
static void LS_API_EXEC(crypto_pwhash_argon2i, crypto_pwhash_argon2i);
static int LS_API_INIT(crypto_pwhash_argon2i, str);
static void LS_API_EXEC(crypto_pwhash_argon2i, str);
static int LS_API_INIT(crypto_pwhash_argon2i, str_verify);
static void LS_API_EXEC(crypto_pwhash_argon2i, str_verify);
static int LS_API_INIT(crypto_pwhash_argon2i, str_needs_rehash);
static void LS_API_EXEC(crypto_pwhash_argon2i, str_needs_rehash);

libsodium_function_t libsodium_functions_crypto_pwhash_argon2i[] = {LS_API_R_ARG0(crypto_pwhash_argon2i, alg_argon2i13),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, bytes_min),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, bytes_max),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, passwd_min),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, passwd_max),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, saltbytes),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, strbytes),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, strprefix),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, opslimit_min),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, opslimit_max),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, memlimit_min),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, memlimit_max),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, opslimit_interactive),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, memlimit_interactive),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, opslimit_moderate),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, memlimit_moderate),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, opslimit_sensitive),
                                                                    LS_API_R_ARG0(crypto_pwhash_argon2i, memlimit_sensitive),
                                                                    LS_API_R_ARGV(crypto_pwhash_argon2i, crypto_pwhash_argon2i, 6),
                                                                    LS_API_R_ARGV(crypto_pwhash_argon2i, str, 3),
                                                                    LS_API_R_ARGV(crypto_pwhash_argon2i, str_verify, 2),
                                                                    LS_API_R_ARGV(crypto_pwhash_argon2i, str_needs_rehash, 3),
                                                                    {NULL}};

/* crypto_pwhash_argon2i_alg_argon2i13/0 */

LS_API_GET_SINT(crypto_pwhash_argon2i, alg_argon2i13);

/* crypto_pwhash_argon2i_bytes_min/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, bytes_min);

/* crypto_pwhash_argon2i_bytes_max/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, bytes_max);

/* crypto_pwhash_argon2i_passwd_min/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, passwd_min);

/* crypto_pwhash_argon2i_passwd_max/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, passwd_max);

/* crypto_pwhash_argon2i_saltbytes/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, saltbytes);

/* crypto_pwhash_argon2i_strbytes/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, strbytes);

/* crypto_pwhash_argon2i_strprefix/0 */

LS_API_GET_STR(crypto_pwhash_argon2i, strprefix);

/* crypto_pwhash_argon2i_opslimit_min/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, opslimit_min);

/* crypto_pwhash_argon2i_opslimit_max/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, opslimit_max);

/* crypto_pwhash_argon2i_memlimit_min/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, memlimit_min);

/* crypto_pwhash_argon2i_memlimit_max/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, memlimit_max);

/* crypto_pwhash_argon2i_opslimit_interactive/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, opslimit_interactive);

/* crypto_pwhash_argon2i_memlimit_interactive/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, memlimit_interactive);

/* crypto_pwhash_argon2i_opslimit_moderate/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, opslimit_moderate);

/* crypto_pwhash_argon2i_memlimit_moderate/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, memlimit_moderate);

/* crypto_pwhash_argon2i_opslimit_sensitive/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, opslimit_sensitive);

/* crypto_pwhash_argon2i_memlimit_sensitive/0 */

LS_API_GET_SIZE(crypto_pwhash_argon2i, memlimit_sensitive);

/* crypto_pwhash_argon2i_crypto_pwhash_argon2i/6 */

typedef struct LS_API_F_ARGV(crypto_pwhash_argon2i, crypto_pwhash_argon2i) {
    unsigned long long outlen;
    const char *passwd;
    unsigned long long passwdlen;
    const unsigned char *salt;
    size_t saltlen;
    unsigned long long opslimit;
    size_t memlimit;
    int alg;
} LS_API_F_ARGV_T(crypto_pwhash_argon2i, crypto_pwhash_argon2i);

static int
LS_API_INIT(crypto_pwhash_argon2i, crypto_pwhash_argon2i)
{
    LS_API_F_ARGV_T(crypto_pwhash_argon2i, crypto_pwhash_argon2i) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long outlen;
    unsigned long long passwdlen;
    size_t saltbytes;
    size_t saltlen;
    unsigned long long opslimit;
    size_t memlimit;
    long alg;
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

    saltbytes = crypto_pwhash_argon2i_saltbytes();

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT || type_length < saltbytes) {
        return -1;
    }

    saltlen = (size_t)(type_length);

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(opslimit)) < 0) {
        return -1;
    }

    if (ei_decode_ulong(buffer, &skip, (unsigned long *)&(memlimit)) < 0) {
        return -1;
    }

    if (ei_decode_long(buffer, &skip, (long *)&(alg)) < 0) {
        return -1;
    }

    x = (ErlDrvSizeT)(passwdlen + saltlen + (sizeof(LS_API_F_ARGV_T(crypto_pwhash_argon2i, crypto_pwhash_argon2i))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_argon2i, crypto_pwhash_argon2i) *)(p);
    argv->outlen = outlen;
    argv->opslimit = opslimit;
    argv->memlimit = memlimit;
    argv->alg = (int)alg;
    p += (sizeof(LS_API_F_ARGV_T(crypto_pwhash_argon2i, crypto_pwhash_argon2i)));
    argv->passwd = (const char *)(p);
    p += passwdlen;
    argv->salt = (const unsigned char *)(p);
    argv->saltlen = saltlen;

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

    request->argv = (void *)(argv);

    return 0;
}

static void
LS_API_EXEC(crypto_pwhash_argon2i, crypto_pwhash_argon2i)
{
    LS_API_F_ARGV_T(crypto_pwhash_argon2i, crypto_pwhash_argon2i) * argv;
    LS_API_READ_ARGV(crypto_pwhash_argon2i, crypto_pwhash_argon2i);

    unsigned char out[argv->outlen];

    LS_SAFE_REPLY(crypto_pwhash_argon2i(out, argv->outlen, argv->passwd, argv->passwdlen, argv->salt, argv->opslimit,
                                        argv->memlimit, argv->alg),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->outlen, ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(out, argv->outlen);
}

/* crypto_pwhash_argon2i_str/3 */

typedef struct LS_API_F_ARGV(crypto_pwhash_argon2i, str) {
    const char *passwd;
    unsigned long long passwdlen;
    unsigned long long opslimit;
    size_t memlimit;
} LS_API_F_ARGV_T(crypto_pwhash_argon2i, str);

static int
LS_API_INIT(crypto_pwhash_argon2i, str)
{
    LS_API_F_ARGV_T(crypto_pwhash_argon2i, str) * argv;
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

    x = (ErlDrvSizeT)(passwdlen + (sizeof(LS_API_F_ARGV_T(crypto_pwhash_argon2i, str))));
    p = (void *)(driver_alloc(x));

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_argon2i, str) *)(p);
    argv->opslimit = opslimit;
    argv->memlimit = memlimit;
    p += (sizeof(LS_API_F_ARGV_T(crypto_pwhash_argon2i, str)));
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
LS_API_EXEC(crypto_pwhash_argon2i, str)
{
    LS_API_F_ARGV_T(crypto_pwhash_argon2i, str) * argv;
    LS_API_READ_ARGV(crypto_pwhash_argon2i, str);

    char out[crypto_pwhash_argon2i_STRBYTES];

    LS_SAFE_REPLY(crypto_pwhash_argon2i_str(out, argv->passwd, argv->passwdlen, argv->opslimit, argv->memlimit),
                  LS_PROTECT({LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), strlen(out), ERL_DRV_TUPLE, 2}),
                  __FILE__, __LINE__);

    (void)sodium_memzero(out, sizeof(out));
}

/* crypto_pwhash_argon2i_str_verify/2 */

typedef struct LS_API_F_ARGV(crypto_pwhash_argon2i, str_verify) {
    const char str[crypto_pwhash_argon2i_STRBYTES];
    const char *passwd;
    unsigned long long passwdlen;
} LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_verify);

static int
LS_API_INIT(crypto_pwhash_argon2i, str_verify)
{
    LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_verify) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long passwdlen;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT ||
        type_length > crypto_pwhash_argon2i_STRBYTES) {
        return -1;
    }

    skip = *index;

    if (ei_skip_term(buffer, &skip) < 0) {
        return -1;
    }

    if (ei_get_type(buffer, &skip, &type, &type_length) < 0 || type != ERL_BINARY_EXT) {
        return -1;
    }

    passwdlen = (unsigned long long)(type_length);

    x = (ErlDrvSizeT)(passwdlen + (sizeof(LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_verify))));
    p = (void *)(driver_alloc(x));
    (void)sodium_memzero(p, x);

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_verify) *)(p);
    p += (sizeof(LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_verify)));
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
LS_API_EXEC(crypto_pwhash_argon2i, str_verify)
{
    LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_verify) * argv;
    LS_API_READ_ARGV(crypto_pwhash_argon2i, str_verify);

    int r = crypto_pwhash_argon2i_str_verify(argv->str, argv->passwd, argv->passwdlen);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_pwhash_argon2i_str_needs_rehash/2 */

typedef struct LS_API_F_ARGV(crypto_pwhash_argon2i, str_needs_rehash) {
    const char str[crypto_pwhash_argon2i_STRBYTES];
    unsigned long long opslimit;
    size_t memlimit;
} LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_needs_rehash);

static int
LS_API_INIT(crypto_pwhash_argon2i, str_needs_rehash)
{
    LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_needs_rehash) * argv;
    int skip;
    int type;
    int type_length;
    unsigned long long opslimit;
    size_t memlimit;
    ErlDrvSizeT x;
    void *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_BINARY_EXT ||
        type_length > crypto_pwhash_argon2i_STRBYTES) {
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

    x = (ErlDrvSizeT)(sizeof(LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_needs_rehash)));
    p = (void *)(driver_alloc(x));
    (void)sodium_memzero(p, x);

    if (p == NULL) {
        return -1;
    }

    argv = (LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_needs_rehash) *)(p);
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
LS_API_EXEC(crypto_pwhash_argon2i, str_needs_rehash)
{
    LS_API_F_ARGV_T(crypto_pwhash_argon2i, str_needs_rehash) * argv;
    LS_API_READ_ARGV(crypto_pwhash_argon2i, str_needs_rehash);

    int r = crypto_pwhash_argon2i_str_needs_rehash(argv->str, argv->opslimit, argv->memlimit);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
