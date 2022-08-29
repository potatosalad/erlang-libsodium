// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef LIBSODIUM_DRV_COMMON_H
#define LIBSODIUM_DRV_COMMON_H

#include <sys/types.h>
#include <erl_driver.h>
#include <ei.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>

extern int	erts_fprintf(FILE *, const char *, ...);

// #define TRACE	1
#ifdef TRACE
	#define TRACE_C(c)	do { putchar(c); fflush(stdout); } while (0)
	#define TRACE_S(s)	do { fputs((s), stdout); fflush(stdout); } while (0)
	#define TRACE_F(...)	erts_fprintf(stderr, __VA_ARGS__)
#else
	#define TRACE_C(c)	((void)(0))
	#define TRACE_S(s)	((void)(0))
	#define TRACE_F(...)	((void)(0))
#endif

/* common */
typedef struct libsodium_drv_term_data {
	ErlDrvTermData	am_ok;
	ErlDrvTermData	am_error;
	ErlDrvTermData	am_undefined;

} libsodium_drv_term_data_t;

extern libsodium_drv_term_data_t	*libsodium_drv;
extern ErlDrvMutex			*libsodium_mutex;

#define LS_ATOM(NAME)		(ErlDrvTermData)(libsodium_drv->am_ ## NAME)
#define LS_STRING(NAME)		(char *)(libsodium_drv->str_ ## NAME)

#define LS_FAIL_BADSPEC(PORT)	(void)(driver_failure_atom(PORT, "bad_spec"))
#define LS_FAIL_OOM(PORT)	(void)(driver_failure_atom(PORT, "out_of_memory"))

#endif
