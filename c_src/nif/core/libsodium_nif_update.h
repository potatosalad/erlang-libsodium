#ifndef LIBSODIUM_NIF_UPDATE_H
#define LIBSODIUM_NIF_UPDATE_H

#include "../libsodium_nif.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Absorbs `inlen` bytes into a state previously copied out of a serialized binary. */
typedef int (*libsodium_nif_update_fun_t)(void *state, const unsigned char *in, unsigned long long inlen);

/*
 * Copy `state_term` into an aligned private state, absorb `input_term` in
 * chunks, and return the updated state as a new binary. Long inputs yield
 * whenever the current timeslice is exhausted; a non-zero return from `fun`
 * is returned to the caller as an integer.
 */
extern ERL_NIF_TERM libsodium_nif_update(ErlNifEnv *env, const char *name, ERL_NIF_TERM state_term, ERL_NIF_TERM input_term,
                                         size_t size, size_t alignment, libsodium_nif_update_fun_t fun);
extern int libsodium_nif_update_load(ErlNifEnv *env);

#ifdef __cplusplus
}
#endif

#endif
