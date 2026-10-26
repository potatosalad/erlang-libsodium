#include "libsodium_nif_update.h"

#include <stdalign.h>

/* States up to this size are updated on the stack when no yield is possible. */
#define LIBSODIUM_NIF_UPDATE_STACK_STATE (1024)
#define LIBSODIUM_NIF_UPDATE_STACK_ALIGN (64)

typedef struct libsodium_nif_update_ctx_s libsodium_nif_update_ctx_t;

struct libsodium_nif_update_ctx_s {
    const char *name;
    libsodium_nif_update_fun_t fun;
    size_t size;
    size_t raw_size;
    void *state;
    unsigned char raw[];
};

static ErlNifResourceType *libsodium_nif_update_resource_type = NULL;

static void libsodium_nif_update_dtor(ErlNifEnv *env, void *obj);
static ERL_NIF_TERM libsodium_nif_update_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM libsodium_nif_update_loop(ErlNifEnv *env, libsodium_nif_update_ctx_t *ctx, ERL_NIF_TERM ctx_term,
                                              ERL_NIF_TERM input_term, const ErlNifBinary *input, size_t offset);

int
libsodium_nif_update_load(ErlNifEnv *env)
{
    ErlNifResourceTypeInit init = {.dtor = libsodium_nif_update_dtor};
    libsodium_nif_update_resource_type =
        enif_init_resource_type(env, "libsodium_nif_update", &init, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    return (libsodium_nif_update_resource_type == NULL) ? -1 : 0;
}

static void
libsodium_nif_update_dtor(ErlNifEnv *env, void *obj)
{
    libsodium_nif_update_ctx_t *ctx = (libsodium_nif_update_ctx_t *)obj;
    (void)env;
    sodium_memzero(ctx->raw, ctx->raw_size);
}

ERL_NIF_TERM
libsodium_nif_update(ErlNifEnv *env, const char *name, ERL_NIF_TERM state_term, ERL_NIF_TERM input_term, size_t size,
                     size_t alignment, libsodium_nif_update_fun_t fun)
{
    ErlNifBinary state_bin;
    ErlNifBinary input;
    libsodium_nif_update_ctx_t *ctx = NULL;
    ERL_NIF_TERM ctx_term;
    uintptr_t address;

    if (!enif_inspect_binary(env, state_term, &state_bin) || state_bin.size != size) {
        return enif_make_badarg(env);
    }
    if (!enif_inspect_binary(env, input_term, &input)) {
        return enif_make_badarg(env);
    }

    if (input.size <= (size_t)(LIBSODIUM_NIF_UPDATE_CHUNK) && size <= LIBSODIUM_NIF_UPDATE_STACK_STATE &&
        alignment <= LIBSODIUM_NIF_UPDATE_STACK_ALIGN) {
        /* Short inputs complete within a single chunk. */
        alignas(LIBSODIUM_NIF_UPDATE_STACK_ALIGN) unsigned char state[LIBSODIUM_NIF_UPDATE_STACK_STATE];
        ERL_NIF_TERM result;
        int rc;
        (void)memcpy(state, state_bin.data, size);
        rc = fun((void *)state, input.data, (unsigned long long)input.size);
        if (rc != 0) {
            result = enif_make_int(env, rc);
        } else {
            result = libsodium_nif_make_binary(env, (const void *)state, size);
        }
        sodium_memzero(state, size);
        return result;
    }

    ctx = (libsodium_nif_update_ctx_t *)enif_alloc_resource(libsodium_nif_update_resource_type,
                                                            sizeof(libsodium_nif_update_ctx_t) + size + alignment);
    if (ctx == NULL) {
        return EXCP_ERROR(env, "Can't allocate libsodium_nif_update resource");
    }
    ctx->name = name;
    ctx->fun = fun;
    ctx->size = size;
    ctx->raw_size = size + alignment;
    address = (uintptr_t)(ctx->raw);
    if (alignment > 1) {
        address = (address + (uintptr_t)(alignment - 1)) & ~((uintptr_t)(alignment - 1));
    }
    ctx->state = (void *)address;
    (void)memcpy(ctx->state, state_bin.data, size);
    ctx_term = enif_make_resource(env, (void *)ctx);
    (void)enif_release_resource((void *)ctx);
    return libsodium_nif_update_loop(env, ctx, ctx_term, input_term, &input, 0);
}

static ERL_NIF_TERM
libsodium_nif_update_continue(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    libsodium_nif_update_ctx_t *ctx = NULL;
    ErlNifBinary input;
    ErlNifUInt64 offset;

    if (argc != 3 || !enif_get_resource(env, argv[0], libsodium_nif_update_resource_type, (void **)&ctx) ||
        !enif_inspect_binary(env, argv[1], &input) || !enif_get_uint64(env, argv[2], &offset) || offset > input.size) {
        return enif_make_badarg(env);
    }
    return libsodium_nif_update_loop(env, ctx, argv[0], argv[1], &input, (size_t)offset);
}

static ERL_NIF_TERM
libsodium_nif_update_loop(ErlNifEnv *env, libsodium_nif_update_ctx_t *ctx, ERL_NIF_TERM ctx_term, ERL_NIF_TERM input_term,
                          const ErlNifBinary *input, size_t offset)
{
    ErlNifTime start = enif_monotonic_time(ERL_NIF_USEC);
    ERL_NIF_TERM result;
    int rc;

    while (offset < input->size) {
        size_t chunk = input->size - offset;
        if (chunk > (size_t)(LIBSODIUM_NIF_UPDATE_CHUNK)) {
            chunk = (size_t)(LIBSODIUM_NIF_UPDATE_CHUNK);
        }
        rc = ctx->fun(ctx->state, input->data + offset, (unsigned long long)chunk);
        if (rc != 0) {
            sodium_memzero(ctx->raw, ctx->raw_size);
            return enif_make_int(env, rc);
        }
        offset += chunk;
        if (offset < input->size) {
            ErlNifTime now = enif_monotonic_time(ERL_NIF_USEC);
            ErlNifTime elapsed = now - start;
            int percent = (int)((elapsed * 100) / 1000);
            start = now;
            if (percent < 1) {
                percent = 1;
            } else if (percent > 100) {
                percent = 100;
            }
            if (enif_consume_timeslice(env, percent)) {
                ERL_NIF_TERM next[3] = {ctx_term, input_term, enif_make_uint64(env, (ErlNifUInt64)(offset))};
                return enif_schedule_nif(env, ctx->name, 0, libsodium_nif_update_continue, 3, next);
            }
        }
    }

    result = libsodium_nif_make_binary(env, ctx->state, ctx->size);
    sodium_memzero(ctx->raw, ctx->raw_size);
    return result;
}
