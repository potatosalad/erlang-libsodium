// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#ifndef LIBSODIUM_PORT_H
#define LIBSODIUM_PORT_H

#include "libsodium_drv_common.h"

typedef struct libsodium_port {
    ErlDrvPort drv_port;
    ErlDrvTermData term_port;
} libsodium_port_t;

extern libsodium_port_t *libsodium_port_alloc(ErlDrvPort drv_port);
extern void libsodium_port_free(libsodium_port_t *port);

#endif