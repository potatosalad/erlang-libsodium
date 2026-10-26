#include "libsodium_nif_state.h"

static void libsodium_nif_state_dtor(ErlNifEnv *env, void *obj);

int
libsodium_nif_state_type_load(ErlNifEnv *env, libsodium_nif_state_type_t *type)
{
    ErlNifResourceTypeInit init = {.dtor = libsodium_nif_state_dtor};
    type->resource_type = enif_init_resource_type(env, type->name, &init, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    return (type->resource_type == NULL) ? -1 : 0;
}

static void
libsodium_nif_state_dtor(ErlNifEnv *env, void *obj)
{
    libsodium_nif_state_t *state = (libsodium_nif_state_t *)obj;
    (void)env;
    sodium_memzero(state->raw, state->raw_size);
}

libsodium_nif_state_t *
libsodium_nif_state_alloc(const libsodium_nif_state_type_t *type)
{
    libsodium_nif_state_t *state = NULL;
    size_t raw_size = type->size + type->alignment;
    uintptr_t address;

    state = (libsodium_nif_state_t *)enif_alloc_resource(type->resource_type, sizeof(libsodium_nif_state_t) + raw_size);
    if (state == NULL) {
        return NULL;
    }
    state->raw_size = raw_size;
    address = (uintptr_t)(state->raw);
    if (type->alignment > 1) {
        address = (address + (uintptr_t)(type->alignment - 1)) & ~((uintptr_t)(type->alignment - 1));
    }
    state->state = (void *)address;
    return state;
}

int
libsodium_nif_state_get(ErlNifEnv *env, ERL_NIF_TERM term, const libsodium_nif_state_type_t *type, libsodium_nif_state_t **state)
{
    return enif_get_resource(env, term, type->resource_type, (void **)state);
}

ERL_NIF_TERM
libsodium_nif_state_make(ErlNifEnv *env, const libsodium_nif_state_type_t *type, const void *source)
{
    libsodium_nif_state_t *state = libsodium_nif_state_alloc(type);
    ERL_NIF_TERM term;

    if (state == NULL) {
        return EXCP_ERROR(env, "Can't allocate libsodium state resource");
    }
    (void)memcpy(state->state, source, type->size);
    term = enif_make_resource(env, (void *)state);
    (void)enif_release_resource((void *)state);
    return term;
}
