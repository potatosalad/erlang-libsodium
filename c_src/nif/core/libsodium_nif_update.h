#ifndef LIBSODIUM_NIF_UPDATE_H
#define LIBSODIUM_NIF_UPDATE_H

#include "libsodium_nif_state.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Absorbs `inlen` bytes into an aligned state. */
typedef int (*libsodium_nif_update_fun_t)(void *state, const unsigned char *in, unsigned long long inlen);

/* The NIF that resumes a yielded update. */
typedef ERL_NIF_TERM (*libsodium_nif_update_next_t)(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

/*
 * Copy the state resource `state_term` of `type` into a new resource, absorb
 * `input_term` into the copy in chunks, and return the new resource. Long
 * inputs yield whenever the current timeslice is exhausted by rescheduling
 * `next` with (new state, input, offset), which must call
 * libsodium_nif_update_continue(). A non-zero result from `fun` is returned
 * to the caller as an integer.
 */
extern ERL_NIF_TERM libsodium_nif_update(ErlNifEnv *env, const char *name, const libsodium_nif_state_type_t *type,
                                         libsodium_nif_update_fun_t fun, libsodium_nif_update_next_t next, ERL_NIF_TERM state_term,
                                         ERL_NIF_TERM input_term);
extern ERL_NIF_TERM libsodium_nif_update_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], const char *name,
                                                  const libsodium_nif_state_type_t *type, libsodium_nif_update_fun_t fun,
                                                  libsodium_nif_update_next_t next);

#ifdef __cplusplus
}
#endif

#endif
