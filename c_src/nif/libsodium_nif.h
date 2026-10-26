#ifndef LIBSODIUM_NIF_H
#define LIBSODIUM_NIF_H

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "erl_nif_trampoline.h"
#include "libsodium_nif_atoms.h"
#include "libsodium_nif_config.h"
#include "core/xnif_trace.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NIF Utility Macros */

#ifndef THE_NON_VALUE
#define THE_NON_VALUE ((ERL_NIF_TERM)0)
#endif

#ifndef ERL_NIF_NORMAL_JOB_BOUND
#define ERL_NIF_NORMAL_JOB_BOUND (0)
#endif

/* All nif functions return a valid value or throws an exception */
#define EXCP(Env, ClassTerm, ReasonString) xnif_raise_exception((Env), __FILE__, __LINE__, (ClassTerm), (ReasonString))

#define EXCP_F(Env, ClassTerm, ReasonFormat, ...)                                                                                  \
    xnif_raise_exception_format((Env), __FILE__, __LINE__, (ClassTerm), (ReasonFormat), __VA_ARGS__)

#define EXCP_NOTSUP(Env, Str) EXCP((Env), ATOM(notsup), (Str))
#define EXCP_BADARG(Env, Str) EXCP((Env), ATOM(badarg), (Str))
#define EXCP_BADARG_F(Env, Fmt, ...) EXCP_F((Env), ATOM(badarg), Fmt, __VA_ARGS__)
#define EXCP_ERROR(Env, Str) EXCP((Env), ATOM(error), (Str))
#define EXCP_ERROR_F(Env, Fmt, ...) EXCP_F((Env), ATOM(error), Fmt, __VA_ARGS__)

/* Scheduling */

/*
 * Reschedule the current call on a dirty CPU scheduler when it would process
 * more than LIBSODIUM_NIF_DIRTY_THRESHOLD bytes on a normal scheduler.
 */
#define LIBSODIUM_NIF_MAYBE_DIRTY(Env, Name, Fun, Argc, Argv, Work)                                                                \
    do {                                                                                                                           \
        if ((Work) > (ErlNifUInt64)(LIBSODIUM_NIF_DIRTY_THRESHOLD) && enif_thread_type() == ERL_NIF_THR_NORMAL_SCHEDULER) {        \
            return enif_schedule_nif((Env), (Name), ERL_NIF_DIRTY_JOB_CPU_BOUND, (Fun), (Argc), (Argv));                           \
        }                                                                                                                          \
    } while (0)

/* Term Helpers */

static inline ERL_NIF_TERM
libsodium_nif_make_binary(ErlNifEnv *env, const void *data, size_t size)
{
    ERL_NIF_TERM term;
    unsigned char *buf = enif_make_new_binary(env, size, &term);
    if (size > 0) {
        (void)memcpy(buf, data, size);
    }
    return term;
}

static inline ERL_NIF_TERM
libsodium_nif_make_string(ErlNifEnv *env, const char *string)
{
    if (string == NULL) {
        return libsodium_nif_make_binary(env, NULL, 0);
    }
    return libsodium_nif_make_binary(env, (const void *)string, strlen(string));
}

#ifdef __cplusplus
}
#endif

#endif
