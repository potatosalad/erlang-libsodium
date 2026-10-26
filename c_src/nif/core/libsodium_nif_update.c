#include "libsodium_nif_update.h"

static ERL_NIF_TERM libsodium_nif_update_loop(ErlNifEnv *env, const char *name, libsodium_nif_update_fun_t fun,
                                              libsodium_nif_update_next_t next, libsodium_nif_state_t *state,
                                              ERL_NIF_TERM state_term, ERL_NIF_TERM input_term, const ErlNifBinary *input,
                                              size_t offset);

ERL_NIF_TERM
libsodium_nif_update(ErlNifEnv *env, const char *name, const libsodium_nif_state_type_t *type, libsodium_nif_update_fun_t fun,
                     libsodium_nif_update_next_t next, ERL_NIF_TERM state_term, ERL_NIF_TERM input_term)
{
    libsodium_nif_state_t *source = NULL;
    libsodium_nif_state_t *state = NULL;
    ErlNifBinary input;
    ERL_NIF_TERM term;

    if (!libsodium_nif_state_get(env, state_term, type, &source) || !enif_inspect_binary(env, input_term, &input)) {
        return enif_make_badarg(env);
    }
    state = libsodium_nif_state_alloc(type);
    if (state == NULL) {
        return EXCP_ERROR(env, "Can't allocate libsodium state resource");
    }
    (void)memcpy(state->state, source->state, type->size);
    term = enif_make_resource(env, (void *)state);
    (void)enif_release_resource((void *)state);
    return libsodium_nif_update_loop(env, name, fun, next, state, term, input_term, &input, 0);
}

ERL_NIF_TERM
libsodium_nif_update_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], const char *name,
                              const libsodium_nif_state_type_t *type, libsodium_nif_update_fun_t fun,
                              libsodium_nif_update_next_t next)
{
    libsodium_nif_state_t *state = NULL;
    ErlNifBinary input;
    ErlNifUInt64 offset;

    if (argc != 3 || !libsodium_nif_state_get(env, argv[0], type, &state) || !enif_inspect_binary(env, argv[1], &input) ||
        !enif_get_uint64(env, argv[2], &offset) || offset > input.size) {
        return enif_make_badarg(env);
    }
    return libsodium_nif_update_loop(env, name, fun, next, state, argv[0], argv[1], &input, (size_t)offset);
}

static ERL_NIF_TERM
libsodium_nif_update_loop(ErlNifEnv *env, const char *name, libsodium_nif_update_fun_t fun, libsodium_nif_update_next_t next,
                          libsodium_nif_state_t *state, ERL_NIF_TERM state_term, ERL_NIF_TERM input_term, const ErlNifBinary *input,
                          size_t offset)
{
    ErlNifTime start = enif_monotonic_time(ERL_NIF_USEC);
    int rc;

    while (offset < input->size) {
        size_t chunk = input->size - offset;
        if (chunk > (size_t)(LIBSODIUM_NIF_UPDATE_CHUNK)) {
            chunk = (size_t)(LIBSODIUM_NIF_UPDATE_CHUNK);
        }
        rc = fun(state->state, input->data + offset, (unsigned long long)chunk);
        if (rc != 0) {
            sodium_memzero(state->raw, state->raw_size);
            return enif_make_int(env, rc);
        }
        offset += chunk;
        if (offset < input->size) {
            ErlNifTime now = enif_monotonic_time(ERL_NIF_USEC);
            int percent = (int)(((now - start) * 100) / 1000);
            start = now;
            if (percent < 1) {
                percent = 1;
            } else if (percent > 100) {
                percent = 100;
            }
            if (enif_consume_timeslice(env, percent)) {
                ERL_NIF_TERM args[3] = {state_term, input_term, enif_make_uint64(env, (ErlNifUInt64)(offset))};
                return enif_schedule_nif(env, name, 0, next, 3, args);
            }
        }
    }

    return state_term;
}
