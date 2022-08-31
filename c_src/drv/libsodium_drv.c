// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_drv.h"
#include "libsodium_port.h"
#include "libsodium_request.h"
#include "libsodium_api.h"

#define INIT_ATOM(NAME) libsodium_drv->am_##NAME = driver_mk_atom(#NAME)

static void
libsodium_drv_misuse_handler(void)
{
    erts_fprintf(stderr, "FATAL ERROR: sodium_misuse() called\n");
    return;
}

/*
 * Erlang DRV functions
 */
static int
libsodium_drv_init(void)
{
    TRACE_F("libsodium_drv_init:%s:%d\n", __FILE__, __LINE__);

    if (libsodium_mutex == NULL) {
        libsodium_mutex = erl_drv_mutex_create("libsodium");
        if (libsodium_mutex == NULL) {
            return -1;
        }
    }

    (void)erl_drv_mutex_lock(libsodium_mutex);

    (void)sodium_set_misuse_handler(NULL);
    (void)sodium_set_misuse_handler(libsodium_drv_misuse_handler);

    if (sodium_init() == -1) {
        (void)erl_drv_mutex_unlock(libsodium_mutex);
        return -1;
    }

    if (libsodium_drv == NULL) {
        libsodium_drv = (libsodium_drv_term_data_t *)(driver_alloc(sizeof(libsodium_drv_term_data_t)));
        if (libsodium_drv == NULL) {
            (void)erl_drv_mutex_unlock(libsodium_mutex);
            return -1;
        }
        INIT_ATOM(ok);
        INIT_ATOM(error);
        INIT_ATOM(undefined);
    }

    (void)init_libsodium_api();

    (void)erl_drv_mutex_unlock(libsodium_mutex);

    return 0;
}

static ErlDrvData
libsodium_drv_start(ErlDrvPort drv_port, char *command)
{
    libsodium_port_t *port;

    (void)command; // Unused

    TRACE_F("libsodium_drv_start:%s:%d\n", __FILE__, __LINE__);

    port = libsodium_port_alloc(drv_port);

    if (port == NULL) {
        return ERL_DRV_ERROR_GENERAL;
    }

    return (ErlDrvData)(port);
}

static void
libsodium_drv_stop(ErlDrvData drv_data)
{
    libsodium_port_t *port;

    TRACE_F("libsodium_drv_stop:%s:%d\n", __FILE__, __LINE__);

    port = (libsodium_port_t *)(drv_data);

    (void)libsodium_port_free(port);
}

static void
libsodium_drv_finish(void)
{
    TRACE_F("libsodium_drv_finish:%s:%d\n", __FILE__, __LINE__);
    if (libsodium_mutex != NULL) {
        (void)erl_drv_mutex_lock(libsodium_mutex);
    }
    if (libsodium_drv != NULL) {
        (void)driver_free(libsodium_drv);
        libsodium_drv = NULL;
    }
    if (libsodium_mutex != NULL) {
        (void)erl_drv_mutex_unlock(libsodium_mutex);
        (void)erl_drv_mutex_destroy(libsodium_mutex);
        libsodium_mutex = NULL;
    }
}

static ErlDrvSSizeT
libsodium_drv_call(ErlDrvData drv_data, unsigned int command, char *buf, ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen,
                   unsigned int *flags)
{
    libsodium_port_t *port;
    ErlDrvTermData caller;
    libsodium_request_t *request;
    ErlDrvSSizeT retval;

    (void)flags; // Unused

    TRACE_F("libsodium_drv_call:%s:%d\n", __FILE__, __LINE__);

    port = (libsodium_port_t *)(drv_data);

    if (port == NULL) {
        return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
    }

    // (void) erl_drv_mutex_lock(libsodium_mutex);
    caller = driver_caller(port->drv_port);
    // (void) erl_drv_mutex_unlock(libsodium_mutex);

    request = libsodium_request_alloc(port, caller, command);

    if (request == NULL) {
        LS_FAIL_OOM(port->drv_port);
        return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
    }

    if (request->error < 0) {
        retval = (ErlDrvSSizeT)(request->error);
        (void)libsodium_request_free(request);
        return retval;
    }

    (void)(request->command)(&request, buf, len);

    if (request->error < 0) {
        retval = (ErlDrvSSizeT)(request->error);
        (void)libsodium_request_free(request);
        return retval;
    }

    retval = (ErlDrvSSizeT)(request->reply.index);

    if (rlen < retval) {
        *rbuf = (char *)(driver_realloc((void *)(*rbuf), (ErlDrvSizeT)(retval)));
        if ((*rbuf) == NULL) {
            (void)libsodium_request_free(request);
            LS_FAIL_OOM(port->drv_port);
            return (ErlDrvSSizeT)(ERL_DRV_ERROR_GENERAL);
        }
    }

    (void)memcpy((void *)(*rbuf), (void *)(request->reply.buff), (size_t)(request->reply.index));

    (void)libsodium_request_free(request);

    return retval;
}

DRIVER_INIT(libsodium_drv)
{
    return &libsodium_driver_entry;
}
