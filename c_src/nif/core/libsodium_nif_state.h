#ifndef LIBSODIUM_NIF_STATE_H
#define LIBSODIUM_NIF_STATE_H

#include "../libsodium_nif.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A libsodium state struct (such as crypto_generichash_state) held in a NIF
 * resource. Each C type has its own resource type, so a state can only be
 * passed to the functions of the API that created it. Resources are never
 * modified after they are returned to Erlang: operations copy the state,
 * advance the copy, and return it as a new resource.
 */
typedef struct libsodium_nif_state_type_s libsodium_nif_state_type_t;
typedef struct libsodium_nif_state_s libsodium_nif_state_t;

struct libsodium_nif_state_type_s {
    const char *name;
    size_t size;
    size_t alignment;
    ErlNifResourceType *resource_type;
};

struct libsodium_nif_state_s {
    void *state;
    size_t raw_size;
    unsigned char raw[];
};

/* Open (or take over) the resource type during load and upgrade. */
extern int libsodium_nif_state_type_load(ErlNifEnv *env, libsodium_nif_state_type_t *type);
/* Allocate a resource holding an uninitialized, aligned state; release it with enif_release_resource(). */
extern libsodium_nif_state_t *libsodium_nif_state_alloc(const libsodium_nif_state_type_t *type);
/* Return 1 and the resource when `term` is a state of `type`, otherwise 0. */
extern int libsodium_nif_state_get(ErlNifEnv *env, ERL_NIF_TERM term, const libsodium_nif_state_type_t *type,
                                   libsodium_nif_state_t **state);
/* Return a new resource holding a copy of `state`, or raise an exception if allocation fails. */
extern ERL_NIF_TERM libsodium_nif_state_make(ErlNifEnv *env, const libsodium_nif_state_type_t *type, const void *state);

#ifdef __cplusplus
}
#endif

#endif
