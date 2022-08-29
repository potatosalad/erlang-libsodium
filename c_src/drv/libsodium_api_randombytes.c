// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_randombytes.h"

static void LS_API_EXEC(randombytes, seedbytes);
static int LS_API_INIT(randombytes, buf);
static void LS_API_EXEC(randombytes, buf);
static void LS_API_EXEC(randombytes, random);
static int LS_API_INIT(randombytes, uniform);
static void LS_API_EXEC(randombytes, uniform);
static void LS_API_EXEC(randombytes, stir);
static void LS_API_EXEC(randombytes, close);
static int LS_API_INIT(randombytes, set_implementation);
static void LS_API_EXEC(randombytes, set_implementation);
static void LS_API_EXEC(randombytes, implementation_name);
static int LS_API_INIT(randombytes, randombytes);
static void LS_API_EXEC(randombytes, randombytes);

libsodium_function_t libsodium_functions_randombytes[] = {LS_API_R_ARG0(randombytes, seedbytes),
                                                          LS_API_R_ARGV(randombytes, buf, 1),
                                                          LS_API_R_ARG0(randombytes, random),
                                                          LS_API_R_ARGV(randombytes, uniform, 1),
                                                          LS_API_R_ARG0(randombytes, stir),
                                                          LS_API_R_ARG0(randombytes, close),
                                                          LS_API_R_ARGV(randombytes, set_implementation, 1),
                                                          LS_API_R_ARG0(randombytes, implementation_name),
                                                          LS_API_R_ARGV(randombytes, randombytes, 1),
                                                          {NULL}};

/* randombytes_seedbytes/0 */

LS_API_GET_SIZE(randombytes, seedbytes);

/* randombytes_buf/1 */

typedef struct LS_API_F_ARGV(randombytes, buf) {
    const size_t size;
} LS_API_F_ARGV_T(randombytes, buf);

static int
LS_API_INIT(randombytes, buf)
{
    LS_API_F_ARGV_T(randombytes, buf) * argv;
    LS_API_INIT_ARGV(randombytes, buf);

    if (ei_decode_ulong(buffer, index, (unsigned long *)&(argv->size)) < 0) {
        (void)driver_free(argv);
        return -1;
    }
    request->argv = (void *)(argv);
    return 0;
}

static void
LS_API_EXEC(randombytes, buf)
{
    LS_API_F_ARGV_T(randombytes, buf) * argv;
    LS_API_READ_ARGV(randombytes, buf);
    void *buf;

    buf = (void *)(driver_alloc((ErlDrvSizeT)(argv->size)));

    if (buf == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)randombytes_buf(buf, argv->size);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(buf), argv->size, ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(buf);
}

/* randombytes_random/0 */

static void
LS_API_EXEC(randombytes, random)
{
    uint32_t n;

    n = randombytes_random();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(n), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* randombytes_uniform/1 */

typedef struct LS_API_F_ARGV(randombytes, uniform) {
    const uint32_t upper_bound;
} LS_API_F_ARGV_T(randombytes, uniform);

static int
LS_API_INIT(randombytes, uniform)
{
    LS_API_F_ARGV_T(randombytes, uniform) * argv;
    LS_API_INIT_ARGV(randombytes, uniform);

    if (ei_decode_ulong(buffer, index, (unsigned long *)&(argv->upper_bound)) < 0) {
        return -1;
    }
    request->argv = (void *)(argv);
    return 0;
}

static void
LS_API_EXEC(randombytes, uniform)
{
    LS_API_F_ARGV_T(randombytes, uniform) * argv;
    LS_API_READ_ARGV(randombytes, uniform);
    uint32_t n;

    n = randombytes_uniform(argv->upper_bound);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(n), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* randombytes_stir/0 */

static void
LS_API_EXEC(randombytes, stir)
{
    (void)randombytes_stir();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_ATOM, LS_ATOM(ok), ERL_DRV_TUPLE, 2};

    if (erl_drv_send_term(request->port->term_port, request->caller, spec, sizeof(spec) / sizeof(spec[0])) < 0) {
        TRACE_F("error sending term\n");
    }

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* randombytes_close/0 */

static void
LS_API_EXEC(randombytes, close)
{
    int r;

    r = randombytes_close();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* randombytes_set_implementation/1 */

typedef struct libsodium_api_randombytes_implementation {
    const char *name;
    randombytes_implementation *impl;
    ErlDrvTermData am_name;
} libsodium_api_randombytes_implementation_t;

static libsodium_api_randombytes_implementation_t libsodium_api_randombytes_implementations[] = {
#ifdef __native_client__
    {"nativeclient", &randombytes_nativeclient_implementation},
#endif
    {"salsa20", &randombytes_salsa20_implementation},
    {"sysrandom", &randombytes_sysrandom_implementation},
    {NULL}};

void
init_libsodium_api_randombytes_implementation(void)
{
    libsodium_api_randombytes_implementation_t *p = NULL;
    for (p = libsodium_api_randombytes_implementations; p->name; p++) {
        p->am_name = driver_mk_atom((char *)(p->name));
    }
}

static libsodium_api_randombytes_implementation_t *
get_libsodium_api_randombytes_implementation(const char *name)
{
    libsodium_api_randombytes_implementation_t *p = NULL;
    ErlDrvTermData am_name;
    (void)erl_drv_mutex_lock(libsodium_mutex);
    am_name = driver_mk_atom((char *)name);
    (void)erl_drv_mutex_unlock(libsodium_mutex);
    for (p = libsodium_api_randombytes_implementations; p->name; p++) {
        if (p->am_name == am_name) {
            return p;
        }
    }
    return NULL;
}

typedef struct LS_API_F_ARGV(randombytes, set_implementation) {
    randombytes_implementation *impl;
} LS_API_F_ARGV_T(randombytes, set_implementation);

static int
LS_API_INIT(randombytes, set_implementation)
{
    LS_API_F_ARGV_T(randombytes, set_implementation) * argv;
    LS_API_INIT_ARGV(randombytes, set_implementation);
    int type;
    int type_length;
    ei_term term;
    libsodium_api_randombytes_implementation_t *p;

    if (ei_get_type(buffer, index, &type, &type_length) < 0 || type != ERL_ATOM_EXT) {
        return -1;
    }
    if (ei_decode_ei_term(buffer, index, &term) < 0) {
        return -1;
    }
    p = get_libsodium_api_randombytes_implementation(term.value.atom_name);
    if (p == NULL) {
        return -1;
    }
    argv->impl = p->impl;
    request->argv = (void *)(argv);
    return 0;
}

static void
LS_API_EXEC(randombytes, set_implementation)
{
    LS_API_F_ARGV_T(randombytes, set_implementation) * argv;
    LS_API_READ_ARGV(randombytes, set_implementation);
    int r;

    r = randombytes_set_implementation(argv->impl);

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* randombytes_implementation_name/0 */

static void
LS_API_EXEC(randombytes, implementation_name)
{
    const char *implementation_name;

    implementation_name = randombytes_implementation_name();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_ATOM, driver_mk_atom((char *)(implementation_name)), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* randombytes_randombytes/1 */

typedef struct LS_API_F_ARGV(randombytes, randombytes) {
    const unsigned long long buf_len;
} LS_API_F_ARGV_T(randombytes, randombytes);

static int
LS_API_INIT(randombytes, randombytes)
{
    LS_API_F_ARGV_T(randombytes, randombytes) * argv;
    LS_API_INIT_ARGV(randombytes, randombytes);

    if (ei_decode_ulong(buffer, index, (unsigned long *)&(argv->buf_len)) < 0) {
        return -1;
    }
    request->argv = (void *)(argv);
    return 0;
}

static void
LS_API_EXEC(randombytes, randombytes)
{
    LS_API_F_ARGV_T(randombytes, randombytes) * argv;
    LS_API_READ_ARGV(randombytes, randombytes);
    unsigned char *buf;

    buf = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->buf_len)));

    if (buf == NULL) {
        LS_FAIL_OOM(request->port->drv_port);
        return;
    }

    (void)randombytes((unsigned char *const)(buf), argv->buf_len);

    ErlDrvTermData spec[] = {LS_RES_TAG(request),         ERL_DRV_BUF2BINARY, (ErlDrvTermData)(buf),
                             (ErlDrvUInt)(argv->buf_len), ERL_DRV_TUPLE,      2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);

    (void)driver_free(buf);
}
