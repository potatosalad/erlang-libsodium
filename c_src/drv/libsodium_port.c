// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_port.h"

libsodium_port_t *
libsodium_port_alloc(ErlDrvPort drv_port)
{
    ErlDrvSizeT x;
    void *p;
    libsodium_port_t *port;

    x = (ErlDrvSizeT)((sizeof(libsodium_port_t)));
    p = driver_alloc(x);

    if (p == NULL) {
        return NULL;
    }

    port = (libsodium_port_t *)(p);
    port->drv_port = drv_port;
    port->term_port = driver_mk_port(drv_port);

    return port;
}

void
libsodium_port_free(libsodium_port_t *port)
{
    if (port == NULL) {
        return;
    }
    (void)driver_free(port);
    port = NULL;
}
