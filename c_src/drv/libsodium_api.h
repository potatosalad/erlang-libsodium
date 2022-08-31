// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#ifndef LIBSODIUM_API_H
#define LIBSODIUM_API_H

#include "libsodium_drv_common.h"
#include "libsodium_request.h"

typedef struct libsodium_function {
    const char *function;
    int arity;
    int (*init)(libsodium_request_t *request, char *buffer, int *index);
    void (*exec)(libsodium_request_t *request);
    ErlDrvTermData am_function;
} libsodium_function_t;

typedef struct libsodium_namespace {
    const char *namespace;
    libsodium_function_t *functions;
    ErlDrvTermData am_namespace;
} libsodium_namespace_t;

extern int erts_fprintf(FILE *stream, const char *format, ...);

extern void init_libsodium_api(void);
extern libsodium_function_t *get_libsodium_api(const char *namespace, const char *function);

#define LS_API_F_NS(NAMESPACE) libsodium_api_##NAMESPACE
#define LS_API_F_FN(FUNCTION) _##FUNCTION
#define LS_API_F0(A, B) A##B
#define LS_API_F1(A, B) LS_API_F0(A, B)
#define LS_API_F2(NAMESPACE, FUNCTION) LS_API_F1(LS_API_F_NS(NAMESPACE), LS_API_F_FN(FUNCTION))

#define LS_API_F_EXEC(NAMESPACE, FUNCTION) LS_API_F2(NAMESPACE, FUNCTION)
#define LS_API_F_INIT(NAMESPACE, FUNCTION) LS_API_F1(LS_API_F_EXEC(NAMESPACE, FUNCTION), _init)
#define LS_API_F_ARGV(NAMESPACE, FUNCTION) LS_API_F1(LS_API_F_EXEC(NAMESPACE, FUNCTION), _argv)
#define LS_API_F_ARGV_T(NAMESPACE, FUNCTION) LS_API_F1(LS_API_F_ARGV(NAMESPACE, FUNCTION), _t)

#define LS_API_EXEC(NAMESPACE, FUNCTION) LS_API_F_EXEC(NAMESPACE, FUNCTION)(libsodium_request_t * request)
#define LS_API_INIT(NAMESPACE, FUNCTION) LS_API_F_INIT(NAMESPACE, FUNCTION)(libsodium_request_t * request, char *buffer, int *index)

#define LS_API_R_ARG0(NAMESPACE, FUNCTION)                                                                                         \
    {                                                                                                                              \
#FUNCTION, 0, NULL, LS_API_F_EXEC(NAMESPACE, FUNCTION)                                                                     \
    }
#define LS_API_R_ARGV(NAMESPACE, FUNCTION, ARITY)                                                                                  \
    {                                                                                                                              \
#FUNCTION, ARITY, LS_API_F_INIT(NAMESPACE, FUNCTION), LS_API_F_EXEC(NAMESPACE, FUNCTION)                                   \
    }

#define LS_API_INIT_ARGV(NAMESPACE, FUNCTION)                                                                                      \
    do {                                                                                                                           \
        argv =                                                                                                                     \
            (LS_API_F_ARGV_T(NAMESPACE, FUNCTION) *)(driver_alloc((ErlDrvSizeT)(sizeof(LS_API_F_ARGV_T(NAMESPACE, FUNCTION)))));   \
        if (argv == NULL) {                                                                                                        \
            return -1;                                                                                                             \
        }                                                                                                                          \
    } while (0)

#define LS_API_READ_ARGV(NAMESPACE, FUNCTION)                                                                                      \
    do {                                                                                                                           \
        if (request->argv == NULL) {                                                                                               \
            return;                                                                                                                \
        }                                                                                                                          \
        argv = (LS_API_F_ARGV_T(NAMESPACE, FUNCTION) *)(request->argv);                                                            \
    } while (0)

#define LS_RES_TAG(REQUEST) ERL_DRV_EXT2TERM, (ErlDrvTermData)(REQUEST->tag.buff), REQUEST->tag.index

#define LS_RESPOND(REQUEST, SPEC, FILE, LINE)                                                                                      \
    do {                                                                                                                           \
        if (erl_drv_send_term(REQUEST->port->term_port, REQUEST->caller, SPEC, sizeof(SPEC) / sizeof(SPEC[0])) < 0) {              \
            TRACE_F("error sending term\n", FILE, LINE);                                                                           \
        }                                                                                                                          \
    } while (0)

#define LS_API_GET_ATOM(NAMESPACE, FUNCTION)                                                                                       \
    static void LS_API_EXEC(NAMESPACE, FUNCTION)                                                                                   \
    {                                                                                                                              \
        const char *retval;                                                                                                        \
        retval = NAMESPACE##_##FUNCTION();                                                                                         \
        ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_ATOM, driver_mk_atom((char *)(retval)), ERL_DRV_TUPLE, 2};           \
        LS_RESPOND(request, spec, __FILE__, __LINE__);                                                                             \
    }

#define LS_API_GET_SINT(NAMESPACE, FUNCTION)                                                                                       \
    static void LS_API_EXEC(NAMESPACE, FUNCTION)                                                                                   \
    {                                                                                                                              \
        int retval;                                                                                                                \
        retval = NAMESPACE##_##FUNCTION();                                                                                         \
        ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(retval), ERL_DRV_TUPLE, 2};                        \
        LS_RESPOND(request, spec, __FILE__, __LINE__);                                                                             \
    }

#define LS_API_GET_SIZE(NAMESPACE, FUNCTION)                                                                                       \
    static void LS_API_EXEC(NAMESPACE, FUNCTION)                                                                                   \
    {                                                                                                                              \
        size_t retval;                                                                                                             \
        retval = NAMESPACE##_##FUNCTION();                                                                                         \
        ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_UINT, (ErlDrvUInt)(retval), ERL_DRV_TUPLE, 2};                       \
        LS_RESPOND(request, spec, __FILE__, __LINE__);                                                                             \
    }

#define LS_API_GET_STR(NAMESPACE, FUNCTION)                                                                                        \
    static void LS_API_EXEC(NAMESPACE, FUNCTION)                                                                                   \
    {                                                                                                                              \
        const char *retval;                                                                                                        \
        retval = NAMESPACE##_##FUNCTION();                                                                                         \
        ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(retval),                                \
                                 strlen(retval),      ERL_DRV_TUPLE,      2};                                                      \
        LS_RESPOND(request, spec, __FILE__, __LINE__);                                                                             \
    }

#define LS_PROTECT(...) __VA_ARGS__

#define LS_SAFE_REPLY(FUNCTION, SPECDATA, FILE, LINE)                                                                              \
    do {                                                                                                                           \
        int r = FUNCTION;                                                                                                          \
        if (r == 0) {                                                                                                              \
            ErlDrvTermData spec[] = SPECDATA;                                                                                      \
            LS_RESPOND(request, spec, FILE, LINE);                                                                                 \
        } else {                                                                                                                   \
            ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};                         \
            LS_RESPOND(request, spec, FILE, LINE);                                                                                 \
        }                                                                                                                          \
    } while (0)

#endif
