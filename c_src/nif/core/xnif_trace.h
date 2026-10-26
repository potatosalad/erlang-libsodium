/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Copyright (c) WhatsApp LLC
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE.md file in the root directory of this source tree.
 */

#ifndef XNIF_TRACE_H
#define XNIF_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../erl_nif_trampoline.h"

// #define XNIF_TRACE_SUPPORTS_BACKTRACE 1

#ifdef XNIF_TRACE_SUPPORTS_BACKTRACE
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

#define XNIF_TRACE_BACKTRACE() ((void)xnif_trace_dump_backtrace())
#else
#define XNIF_TRACE_BACKTRACE() ((void)(0))
#endif

#define XNIF_TRACE_USE_STDERR 1

// #define XNIF_TRACE 1
#ifdef XNIF_TRACE
#define XNIF_TRACE_C(c)                                                                                                            \
    do {                                                                                                                           \
        enif_fprintf(stdout, "%c", (c));                                                                                           \
    } while (0)
#define XNIF_TRACE_S(s)                                                                                                            \
    do {                                                                                                                           \
        enif_fprintf(stdout, "%s", (s));                                                                                           \
    } while (0)
#define XNIF_TRACE_F(...)                                                                                                          \
    do {                                                                                                                           \
        xnif_trace_printf(__VA_ARGS__);                                                                                            \
    } while (0)
#else
#define XNIF_TRACE_C(c) ((void)(0))
#define XNIF_TRACE_S(s) ((void)(0))
#define XNIF_TRACE_F(...) ((void)(0))
#endif

extern ERL_NIF_TERM xnif_make_string_printf(ErlNifEnv *env, const char *format, ...);
extern ERL_NIF_TERM xnif_make_string_vprintf(ErlNifEnv *env, const char *format, va_list ap);
static ERL_NIF_TERM xnif_raise_exception(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term,
                                         const char *reason_string);
static ERL_NIF_TERM xnif_raise_exception_format(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term,
                                                const char *reason_format, ...);
static ERL_NIF_TERM xnif_raise_exception_vformat(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term,
                                                 const char *reason_format, va_list ap);

inline ERL_NIF_TERM
xnif_raise_exception(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term, const char *reason_string)
{
    ERL_NIF_TERM stacktrace_term;
    ERL_NIF_TERM reason_term;
    ERL_NIF_TERM error_term;
    stacktrace_term = enif_make_tuple2(env, enif_make_string(env, file, ERL_NIF_LATIN1), enif_make_int(env, line));
    reason_term = enif_make_string(env, reason_string, ERL_NIF_LATIN1);
    error_term = enif_make_tuple3(env, class_term, stacktrace_term, reason_term);
    return enif_raise_exception(env, error_term);
}

inline ERL_NIF_TERM
xnif_raise_exception_format(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term, const char *reason_format, ...)
{
    ERL_NIF_TERM exception_term;
    va_list arglist;
    va_start(arglist, reason_format);
    exception_term = xnif_raise_exception_vformat(env, file, line, class_term, reason_format, arglist);
    va_end(arglist);
    return exception_term;
}

inline ERL_NIF_TERM
xnif_raise_exception_vformat(ErlNifEnv *env, const char *file, int line, ERL_NIF_TERM class_term, const char *reason_format,
                             va_list ap)
{
    ERL_NIF_TERM stacktrace_term;
    ERL_NIF_TERM reason_term;
    ERL_NIF_TERM error_term;
    stacktrace_term = enif_make_tuple2(env, enif_make_string(env, file, ERL_NIF_LATIN1), enif_make_int(env, line));
    reason_term = xnif_make_string_vprintf(env, reason_format, ap);
    error_term = enif_make_tuple3(env, class_term, stacktrace_term, reason_term);
    return enif_raise_exception(env, error_term);
}

#ifdef XNIF_TRACE
typedef struct xnif_debug_file_s xnif_debug_file_t;
extern xnif_debug_file_t *xnif_debug_file;

static int xnif_trace_printf(const char *format, ...);
extern int xnif_trace_vprintf(const char *format, va_list ap);

inline int
xnif_trace_printf(const char *format, ...)
{
    int ret;
    va_list arglist;
    va_start(arglist, format);
    ret = xnif_trace_vprintf(format, arglist);
    va_end(arglist);
    return ret;
}
#endif

#ifdef XNIF_TRACE_SUPPORTS_BACKTRACE
static void xnif_trace_dump_backtrace(void);

#ifdef XNIF_TRACE
#define XNIF_BACKTRACE_F(...)                                                                                                      \
    do {                                                                                                                           \
        xnif_trace_printf(__VA_ARGS__);                                                                                            \
    } while (0)
#else
#define XNIF_BACKTRACE_F(...)                                                                                                      \
    do {                                                                                                                           \
        enif_fprintf(stderr, __VA_ARGS__);                                                                                         \
    } while (0)
#endif

inline void
xnif_trace_dump_backtrace(void)
{
#define XNIF_TRACE_CALLER_DEPTH (10)
    void *frames[XNIF_TRACE_CALLER_DEPTH];
    size_t size;
    char **strings;
    size_t i;

    size = backtrace(frames, XNIF_TRACE_CALLER_DEPTH);
    strings = backtrace_symbols(frames, size);
    if (strings == NULL) {
        return;
    }
    XNIF_BACKTRACE_F("\tObtained %u stack frames...\n", size);
    for (i = 0; i < size; i++) {
        XNIF_BACKTRACE_F("\t%s\n", strings[i]);
    }
    (void)free(strings);
    return;
#undef XNIF_TRACE_CALLER_DEPTH
}

#undef XNIF_BACKTRACE_F

#endif

#ifdef __cplusplus
}
#endif

#endif
