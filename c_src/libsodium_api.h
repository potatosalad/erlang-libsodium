// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef LIBSODIUM_API_H
#define LIBSODIUM_API_H

#include "libsodium_drv_common.h"
#include "libsodium_request.h"

typedef struct libsodium_function {
	const char		*function;
	int			arity;
	int			(*init)(libsodium_request_t *request, char *buffer, int *index);
	void			(*exec)(libsodium_request_t *request);
	ErlDrvTermData		am_function;
} libsodium_function_t;

typedef struct libsodium_namespace {
	const char		*namespace;
	libsodium_function_t	*functions;
	ErlDrvTermData		am_namespace;
} libsodium_namespace_t;

extern void			init_libsodium_api(void);
extern libsodium_function_t	*get_libsodium_api(const char *namespace, const char *function);

#define LS_API_F_NS(NAMESPACE)			libsodium_api_ ## NAMESPACE
#define LS_API_F_FN(FUNCTION)			_ ## FUNCTION
#define LS_API_F0(A, B)				A ## B
#define LS_API_F1(A, B)				LS_API_F0(A, B)
#define LS_API_F2(NAMESPACE, FUNCTION)		LS_API_F1(LS_API_F_NS(NAMESPACE), LS_API_F_FN(FUNCTION))

#define LS_API_F_EXEC(NAMESPACE, FUNCTION)	LS_API_F2(NAMESPACE, FUNCTION)
#define LS_API_F_INIT(NAMESPACE, FUNCTION)	LS_API_F1(LS_API_F_EXEC(NAMESPACE, FUNCTION), _init)
#define LS_API_F_ARGV(NAMESPACE, FUNCTION)	LS_API_F1(LS_API_F_EXEC(NAMESPACE, FUNCTION), _argv)
#define LS_API_F_ARGV_T(NAMESPACE, FUNCTION)	LS_API_F1(LS_API_F_ARGV(NAMESPACE, FUNCTION), _t)

#define LS_API_EXEC(NAMESPACE, FUNCTION)	LS_API_F_EXEC(NAMESPACE, FUNCTION) (libsodium_request_t *request)
#define LS_API_INIT(NAMESPACE, FUNCTION)	LS_API_F_INIT(NAMESPACE, FUNCTION) (libsodium_request_t *request, char *buffer, int *index)

#define LS_API_R_ARG0(NAMESPACE, FUNCTION)		{ #FUNCTION, 0, NULL, LS_API_F_EXEC(NAMESPACE, FUNCTION) }
#define LS_API_R_ARGV(NAMESPACE, FUNCTION, ARITY)	{ #FUNCTION, ARITY, LS_API_F_INIT(NAMESPACE, FUNCTION), LS_API_F_EXEC(NAMESPACE, FUNCTION) }

#define LS_API_INIT_ARGV(NAMESPACE, FUNCTION)	\
	do {	\
		argv = (LS_API_F_ARGV_T(NAMESPACE, FUNCTION) *)(driver_alloc((ErlDrvSizeT)(sizeof (LS_API_F_ARGV_T(NAMESPACE, FUNCTION)))));	\
		if (argv == NULL) {	\
			return -1;	\
		}	\
	} while (0)

#define LS_API_READ_ARGV(NAMESPACE, FUNCTION)	\
	do {	\
		argv = (LS_API_F_ARGV_T(NAMESPACE, FUNCTION) *)(request->argv);	\
	} while (0)

#define LS_RES_TAG(REQUEST)	ERL_DRV_EXT2TERM, (ErlDrvTermData)(REQUEST->tag.buff), REQUEST->tag.index

#define LS_RESPOND(REQUEST, SPEC, FILE, LINE)	\
	do {	\
		if (erl_drv_send_term(REQUEST->port->term_port, REQUEST->caller, SPEC, sizeof(SPEC) / sizeof(SPEC[0])) < 0) {	\
			TRACE_F("error sending term\n", FILE, LINE);	\
		}	\
	} while (0)

#endif
