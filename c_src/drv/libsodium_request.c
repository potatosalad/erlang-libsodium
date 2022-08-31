// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_request.h"
#include "libsodium_api.h"

static void libsodium_request_badarg(libsodium_request_t *request);

static void libsodium_async_call(libsodium_request_t **request, char *buf, ErlDrvSizeT len);
static void libsodium_async_call_invoke(void *async_data);
static void libsodium_async_call_free(void *async_data);

libsodium_request_t *
libsodium_request_alloc(libsodium_port_t *port, ErlDrvTermData caller, unsigned int command)
{
    ErlDrvSizeT x;
    void *p;
    libsodium_request_t *request;

    x = (ErlDrvSizeT)((sizeof(libsodium_request_t)));
    p = driver_alloc(x);

    if (p == NULL) {
        return NULL;
    }

    request = (libsodium_request_t *)(p);
    request->port = port;
    request->caller = caller;
    request->command = NULL;
    request->tag.buff = NULL;
    request->tag.buffsz = 0;
    request->tag.index = 0;
    request->argc = -1;
    request->argv = NULL;
    request->execute = NULL;
    request->error = 0;
    request->reply.buff = NULL;
    request->reply.buffsz = 0;
    request->reply.index = 0;

    switch (command) {
    case LIBSODIUM_ASYNC_CALL:
        request->command = libsodium_async_call;
        break;
    default:
        (void)libsodium_request_badarg(request);
        break;
    }

    return request;
}

void
libsodium_request_free(libsodium_request_t *request)
{
    if (request == NULL) {
        return;
    }
    if (request->tag.buff != NULL) {
        (void)driver_free(request->tag.buff);
        request->tag.buff = NULL;
        request->tag.buffsz = 0;
        request->tag.index = 0;
    }
    if (request->argv != NULL) {
        (void)driver_free(request->argv);
        request->argv = NULL;
    }
    if (request->reply.buff != NULL) {
        (void)driver_free(request->reply.buff);
        request->reply.buff = NULL;
        request->reply.buffsz = 0;
        request->reply.index = 0;
    }
    (void)driver_free(request);
    request = NULL;
}

static void
libsodium_request_badarg(libsodium_request_t *request)
{
    request->error = (ErlDrvSSizeT)(ERL_DRV_ERROR_BADARG);
}

static void
libsodium_async_call(libsodium_request_t **request, char *buf, ErlDrvSizeT len)
{
    libsodium_request_t *req;
    libsodium_request_t *sync_req;
    char *buffer;
    int version;
    int version_beg;
    int version_end;
    int index;
    int tag_beg;
    int tag_end;
    int type;
    int type_length;
    int arity;
    libsodium_function_t *function;
    void *async_data;

    (void)len; // unused

    req = *request;
    buffer = buf;
    index = 0;

    version_beg = index;

    if (ei_decode_version(buffer, &index, &version) < 0) {
        (void)libsodium_request_badarg(req);
        return;
    }

    version_end = index;

    if (ei_decode_tuple_header(buffer, &index, &arity) < 0 || arity != 4) {
        (void)libsodium_request_badarg(req);
        return;
    }

    if (ei_get_type(buffer, &index, &type, &type_length) < 0 || (type != ERL_REFERENCE_EXT && type != ERL_NEW_REFERENCE_EXT)) {
        (void)libsodium_request_badarg(req);
        return;
    }

    tag_beg = index;

    if (ei_skip_term(buffer, &index) < 0) {
        (void)libsodium_request_badarg(req);
        return;
    }

    tag_end = index;

    req->tag.buffsz = (version_end - version_beg) + (tag_end - tag_beg);
    req->tag.index = req->tag.buffsz;
    req->tag.buff = (char *)(driver_alloc(req->tag.buffsz));

    if (req->tag.buff == NULL) {
        (void)libsodium_request_badarg(req);
        LS_FAIL_OOM(req->port->drv_port);
        return;
    }

    (void)memcpy((req->tag.buff) + version_beg, buf + version_beg, (version_end - version_beg));
    (void)memcpy((req->tag.buff) + (version_end - version_beg), buf + tag_beg, (tag_end - tag_beg));

    if (ei_get_type(buffer, &index, &type, &type_length) < 0 || type != ERL_ATOM_EXT) {
        (void)libsodium_request_badarg(req);
        return;
    }

    if (ei_decode_ei_term(buffer, &index, &(req->namespace)) < 0) {
        (void)libsodium_request_badarg(req);
        return;
    }

    if (ei_get_type(buffer, &index, &type, &type_length) < 0 || type != ERL_ATOM_EXT) {
        (void)libsodium_request_badarg(req);
        return;
    }

    if (ei_decode_ei_term(buffer, &index, &(req->function)) < 0) {
        (void)libsodium_request_badarg(req);
        return;
    }

    if (ei_decode_tuple_header(buffer, &index, &(req->argc)) < 0) {
        (void)libsodium_request_badarg(req);
        return;
    }

    function = get_libsodium_api(req->namespace.value.atom_name, req->function.value.atom_name);

    if (function == NULL || function->arity != req->argc) {
        (void)libsodium_request_badarg(req);
        return;
    }

    if (function->init != NULL && function->init(req, buffer, &index) < 0) {
        (void)libsodium_request_badarg(req);
        return;
    }

    req->execute = function->exec;

    sync_req = libsodium_request_alloc(req->port, req->caller, LIBSODIUM_ASYNC_CALL);

    if (sync_req == NULL) {
        (void)libsodium_request_badarg(req);
        LS_FAIL_OOM(req->port->drv_port);
        return;
    }

    sync_req->tag.buffsz = req->tag.buffsz;
    sync_req->tag.index = req->tag.index;
    sync_req->tag.buff = (char *)(driver_alloc(sync_req->tag.buffsz));

    if (sync_req->tag.buff == NULL) {
        (void)libsodium_request_free(sync_req);
        (void)libsodium_request_badarg(req);
        LS_FAIL_OOM(req->port->drv_port);
        return;
    }

    (void)memcpy(sync_req->tag.buff, req->tag.buff, sync_req->tag.buffsz);

    sync_req->reply.buffsz = sync_req->tag.buffsz;
    sync_req->reply.index = sync_req->tag.index;
    sync_req->reply.buff = (char *)(driver_alloc(sync_req->reply.buffsz));

    if (sync_req->reply.buff == NULL) {
        (void)libsodium_request_free(sync_req);
        (void)libsodium_request_badarg(req);
        LS_FAIL_OOM(req->port->drv_port);
        return;
    }

    (void)memcpy(sync_req->reply.buff, sync_req->tag.buff, sync_req->reply.buffsz);

    sync_req->namespace = req->namespace;
    sync_req->function = req->function;
    sync_req->argc = req->argc;
    sync_req->argv = NULL;
    sync_req->execute = req->execute;
    sync_req->error = req->error;

    async_data = (void *)(req);
    *request = sync_req;

    if (driver_async(req->port->drv_port, NULL, libsodium_async_call_invoke, async_data, libsodium_async_call_free) < 0) {
        (void)libsodium_request_badarg(sync_req);
        return;
    }
}

static void
libsodium_async_call_invoke(void *async_data)
{
    libsodium_request_t *request;

    request = (libsodium_request_t *)(async_data);

    if (request == NULL) {
        return;
    }

    // TRACE_F("(invoke) asynchronous call: %s\n", request->function.value.atom_name);

    (void)(request->execute)(request);
}

static void
libsodium_async_call_free(void *async_data)
{
    libsodium_request_t *request;

    request = (libsodium_request_t *)(async_data);

    if (request == NULL) {
        return;
    }

    // TRACE_F("(free) asynchronous call: %s\n", request->function.value.atom_name);

    (void)libsodium_request_free(request);
}
