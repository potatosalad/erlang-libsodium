/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Copyright (c) WhatsApp LLC
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE.md file in the root directory of this source tree.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "xnif_trace.h"
#ifdef XNIF_TRACE
#include <stdatomic.h>
#endif

/* Raise {vsnprintf, Errno} with Errno a positive errno value. */
static ERL_NIF_TERM xnif_raise_vsnprintf(ErlNifEnv *env, int err);

inline ERL_NIF_TERM
xnif_raise_vsnprintf(ErlNifEnv *env, int err)
{
    return enif_raise_exception(env, enif_make_tuple2(env, enif_make_atom(env, "vsnprintf"), enif_make_int(env, err)));
}

ERL_NIF_TERM
xnif_make_string_printf(ErlNifEnv *env, const char *format, ...)
{
    ERL_NIF_TERM ret;
    va_list arglist;
    va_start(arglist, format);
    ret = xnif_make_string_vprintf(env, format, arglist);
    va_end(arglist);
    return ret;
}

/*
 * Format with enif_vsnprintf (C99 semantics plus %T) and return the result as
 * a Latin-1 charlist, with no length limit.
 *
 * Raises {vsnprintf, Errno} if formatting fails or the output grew between
 * passes, and enomem if a heap buffer is needed and can't be allocated.
 *
 * Never consumes the caller's va_list. Requires the process-bound env the NIF
 * was invoked with: enif_raise_exception stores into env->proc, so with an
 * enif_alloc_env environment the exception would be silently lost.
 */
ERL_NIF_TERM
xnif_make_string_vprintf(ErlNifEnv *env, const char *format, va_list ap)
{
    char stack_buf[256];
    char *big;
    va_list ap2;
    int n, n2;
    ERL_NIF_TERM term;

    /* Pass 1: stack buffer. Work on a copy so ap stays valid for pass 2. */
    va_copy(ap2, ap);
    n = enif_vsnprintf(stack_buf, sizeof stack_buf, format, ap2);
    va_end(ap2);

    if (n < 0)
        return xnif_raise_vsnprintf(env, -n);
    if ((size_t)n < sizeof stack_buf)
        return enif_make_string_len(env, stack_buf, (size_t)n, ERL_NIF_LATIN1);

    /* Pass 2: exact-size heap buffer. n excludes the NUL enif_vsnprintf writes. */
    big = enif_alloc((size_t)n + 1);
    if (big == NULL)
        return enif_raise_exception(env, enif_make_atom(env, "enomem"));

    va_copy(ap2, ap);
    n2 = enif_vsnprintf(big, (size_t)n + 1, format, ap2);
    va_end(ap2);

    /* Pass 2's count is the truth. Growth means it was truncated; shrinkage
     * is fine, since the first n2 bytes are all written. */
    if (n2 < 0 || n2 > n) {
        (void)enif_free(big);
        return xnif_raise_vsnprintf(env, n2 < 0 ? -n2 : EOVERFLOW);
    }

    term = enif_make_string_len(env, big, (size_t)n2, ERL_NIF_LATIN1);
    (void)enif_free(big);
    return term;
}

#ifdef XNIF_TRACE
struct xnif_debug_file_s {
    atomic_flag mtx;
    FILE *stream;
};

static xnif_debug_file_t xnif_debug_file_default = {
    .mtx = ATOMIC_FLAG_INIT,
    .stream = NULL,
};
xnif_debug_file_t *xnif_debug_file = &xnif_debug_file_default;

int
xnif_trace_vprintf(const char *format, va_list ap)
{
    int res = 0;
    while (atomic_flag_test_and_set_explicit(&xnif_debug_file->mtx, memory_order_acquire)) {
    }
#ifdef XNIF_TRACE_USE_STDERR
    if (xnif_debug_file->stream == NULL) {
        xnif_debug_file->stream = stderr;
    }
#else
    if (xnif_debug_file->stream == NULL) {
        static char suffix[256];
        static char filename[256];
        static pid_t pid;
        static time_t now;
        static struct tm *timenow;

        pid = getpid();
        now = time(NULL);
        timenow = gmtime(&now);
        (void)strftime(suffix, sizeof(suffix), "%Y-%m-%d_%H:%M:%S", timenow);
        (void)snprintf(filename, sizeof(filename), "/tmp/xnif-trace.%u.%s.log", pid, suffix);
        xnif_debug_file->stream = fopen(filename, "w");
    }
#endif
    res += enif_fprintf(xnif_debug_file->stream, "[%u.%p:%llu] ", getpid(), (void *)enif_thread_self(),
                        (uint64_t)enif_monotonic_time(ERL_NIF_NSEC));
    res += enif_vfprintf(xnif_debug_file->stream, format, ap);
    atomic_flag_clear_explicit(&xnif_debug_file->mtx, memory_order_release);
    return res;
}
#endif
