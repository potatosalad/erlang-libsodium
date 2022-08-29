// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#ifndef LIBSODIUM_DRV_H
#define LIBSODIUM_DRV_H

#include "libsodium_drv_common.h"

libsodium_drv_term_data_t *libsodium_drv;
ErlDrvMutex *libsodium_mutex;

/*
 * Erlang DRV functions
 */
static int libsodium_drv_init(void);
static ErlDrvData libsodium_drv_start(ErlDrvPort drv_port, char *command);
static void libsodium_drv_stop(ErlDrvData drv_data);
static void libsodium_drv_finish(void);
static ErlDrvSSizeT libsodium_drv_call(ErlDrvData drv_data, unsigned int command, char *buf, ErlDrvSizeT len, char **rbuf,
                                       ErlDrvSizeT rlen, unsigned int *flags);

static ErlDrvEntry libsodium_driver_entry = {
    libsodium_drv_init,             /* F_PTR init, called when driver is loaded */
    libsodium_drv_start,            /* L_PTR start, called when port is opened */
    libsodium_drv_stop,             /* F_PTR stop, called when port is closed */
    NULL,                           /* F_PTR output, called when erlang has sent */
    NULL,                           /* F_PTR ready_input, called when input descriptor ready */
    NULL,                           /* F_PTR ready_output, called when output descriptor ready */
    "libsodium_drv",                /* char *driver_name, the argument to open_port */
    libsodium_drv_finish,           /* F_PTR finish, called when unloaded */
    NULL,                           /* void *handle, Reserved by VM */
    NULL,                           /* F_PTR control, port_command callback */
    NULL,                           /* F_PTR timeout, reserved */
    NULL,                           /* F_PTR outputv, reserved */
    NULL,                           /* F_PTR ready_async, only for async drivers */
    NULL,                           /* F_PTR flush, called when port is about to be closed, but there is data in driver queue */
    libsodium_drv_call,             /* F_PTR call, much like control, sync call to driver */
    NULL,                           /* F_PTR event, called when an event selected by driver_event() occurs. */
    ERL_DRV_EXTENDED_MARKER,        /* int extended marker, Should always be set to indicate driver versioning */
    ERL_DRV_EXTENDED_MAJOR_VERSION, /* int major_version, should always be set to this value */
    ERL_DRV_EXTENDED_MINOR_VERSION, /* int minor_version, should always be set to this value */
    ERL_DRV_FLAG_USE_PORT_LOCKING,  /* int driver_flags, see documentation */
    NULL,                           /* void *handle2, reserved for VM use */
    NULL,                           /* F_PTR process_exit, called when a monitored process dies */
    NULL                            /* F_PTR stop_select, called to close an event object */
};

#endif
