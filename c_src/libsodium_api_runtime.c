// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libsodium_api_runtime.h"

static void	LS_API_EXEC(runtime, has_neon);
static void	LS_API_EXEC(runtime, has_sse2);
static void	LS_API_EXEC(runtime, has_sse3);
static void	LS_API_EXEC(runtime, has_ssse3);
static void	LS_API_EXEC(runtime, has_sse41);
static void	LS_API_EXEC(runtime, has_avx);
static void	LS_API_EXEC(runtime, has_pclmul);
static void	LS_API_EXEC(runtime, has_aesni);

libsodium_function_t	libsodium_functions_runtime[] = {
	LS_API_R_ARG0(runtime, has_neon),
	LS_API_R_ARG0(runtime, has_sse2),
	LS_API_R_ARG0(runtime, has_sse3),
	LS_API_R_ARG0(runtime, has_ssse3),
	LS_API_R_ARG0(runtime, has_sse41),
	LS_API_R_ARG0(runtime, has_avx),
	LS_API_R_ARG0(runtime, has_pclmul),
	LS_API_R_ARG0(runtime, has_aesni),
	{NULL}
};

#define LS_API_RUNTIME_HAS(FEATURE, FILE, LINE)	\
	static void	\
	LS_API_EXEC(runtime, has_ ## FEATURE)	\
	{	\
		int r;	\
		r = sodium_runtime_has_ ## FEATURE ();	\
		ErlDrvTermData spec[] = {	\
			LS_RES_TAG(request),	\
			ERL_DRV_INT, (ErlDrvSInt)(r),	\
			ERL_DRV_TUPLE, 2	\
		};	\
		LS_RESPOND(request, spec, FILE, LINE);	\
	}

/* runtime_has_neon/0 */

LS_API_RUNTIME_HAS(neon, __FILE__, __LINE__);

/* runtime_has_sse2/0 */

LS_API_RUNTIME_HAS(sse2, __FILE__, __LINE__);

/* runtime_has_sse3/0 */

LS_API_RUNTIME_HAS(sse3, __FILE__, __LINE__);

/* runtime_has_ssse3/0 */

LS_API_RUNTIME_HAS(ssse3, __FILE__, __LINE__);

/* runtime_has_sse41/0 */

LS_API_RUNTIME_HAS(sse41, __FILE__, __LINE__);

/* runtime_has_avx/0 */

LS_API_RUNTIME_HAS(avx, __FILE__, __LINE__);

/* runtime_has_pclmul/0 */

LS_API_RUNTIME_HAS(pclmul, __FILE__, __LINE__);

/* runtime_has_aesni/0 */

LS_API_RUNTIME_HAS(aesni, __FILE__, __LINE__);
