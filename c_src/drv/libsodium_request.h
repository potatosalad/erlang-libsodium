// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#ifndef LIBSODIUM_REQUEST_H
#define LIBSODIUM_REQUEST_H

#include "libsodium_drv_common.h"
#include "libsodium_port.h"

#define LIBSODIUM_ASYNC_CALL 1

typedef struct libsodium_request {
    libsodium_port_t *port;
    ErlDrvTermData caller;
    void (*command)(struct libsodium_request **, char *, ErlDrvSizeT);
    ei_x_buff tag;
    ei_term namespace;
    ei_term function;
    int argc;
    void *argv;
    void (*execute)(struct libsodium_request *);
    ErlDrvSSizeT error;
    ei_x_buff reply;
} libsodium_request_t;

extern libsodium_request_t *libsodium_request_alloc(libsodium_port_t *port, ErlDrvTermData caller, unsigned int command);
extern void libsodium_request_free(libsodium_request_t *request);

#endif