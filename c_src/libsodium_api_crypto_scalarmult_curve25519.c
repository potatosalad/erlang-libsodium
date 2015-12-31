// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libsodium_api_crypto_scalarmult_curve25519.h"

static void	LS_API_EXEC(crypto_scalarmult_curve25519, bytes);
static void	LS_API_EXEC(crypto_scalarmult_curve25519, scalarbytes);
static int	LS_API_INIT(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519);
static void	LS_API_EXEC(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519);
static int	LS_API_INIT(crypto_scalarmult_curve25519, base);
static void	LS_API_EXEC(crypto_scalarmult_curve25519, base);

libsodium_function_t	libsodium_functions_crypto_scalarmult_curve25519[] = {
	LS_API_R_ARG0(crypto_scalarmult_curve25519, bytes),
	LS_API_R_ARG0(crypto_scalarmult_curve25519, scalarbytes),
	LS_API_R_ARGV(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519, 2),
	LS_API_R_ARGV(crypto_scalarmult_curve25519, base, 1),
	{NULL}
};

/* crypto_scalarmult_curve25519_bytes/0 */

static void
LS_API_EXEC(crypto_scalarmult_curve25519, bytes)
{
	size_t bytes;

	bytes = crypto_scalarmult_curve25519_bytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(bytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_scalarmult_curve25519_scalarbytes/0 */

static void
LS_API_EXEC(crypto_scalarmult_curve25519, scalarbytes)
{
	size_t scalarbytes;

	scalarbytes = crypto_scalarmult_curve25519_scalarbytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(scalarbytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_scalarmult_curve25519_crypto_scalarmult_curve25519/2 */

typedef struct LS_API_F_ARGV(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519) {
	const unsigned char	*n;
	const unsigned char	*p;
} LS_API_F_ARGV_T(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519);

static int
LS_API_INIT(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519)
{
	LS_API_F_ARGV_T(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519) *argv;
	int skip;
	int type;
	int type_length;
	size_t scalarbytes;
	ErlDrvSizeT x;
	void *p;

	scalarbytes = crypto_scalarmult_curve25519_scalarbytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != scalarbytes) {
		return -1;
	}

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != scalarbytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(scalarbytes + scalarbytes + (sizeof (LS_API_F_ARGV_T(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519)));
	argv->n = (const unsigned char *)(p);
	p += scalarbytes;
	argv->p = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->p), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519)
{
	LS_API_F_ARGV_T(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519) *argv;
	LS_API_READ_ARGV(crypto_scalarmult_curve25519, crypto_scalarmult_curve25519);
	size_t bytes;
	unsigned char *q;

	bytes = crypto_scalarmult_curve25519_bytes();
	q = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

	if (q == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_scalarmult_curve25519(q, argv->n, argv->p);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(q), bytes,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(q);
}

/* crypto_scalarmult_curve25519_base/1 */

typedef struct LS_API_F_ARGV(crypto_scalarmult_curve25519, base) {
	const unsigned char	*n;
} LS_API_F_ARGV_T(crypto_scalarmult_curve25519, base);

static int
LS_API_INIT(crypto_scalarmult_curve25519, base)
{
	LS_API_F_ARGV_T(crypto_scalarmult_curve25519, base) *argv;
	int type;
	int type_length;
	size_t scalarbytes;
	ErlDrvSizeT x;
	void *p;

	scalarbytes = crypto_scalarmult_curve25519_scalarbytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != scalarbytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(scalarbytes + (sizeof (LS_API_F_ARGV_T(crypto_scalarmult_curve25519, base))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_scalarmult_curve25519, base) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_scalarmult_curve25519, base)));
	argv->n = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_scalarmult_curve25519, base)
{
	LS_API_F_ARGV_T(crypto_scalarmult_curve25519, base) *argv;
	LS_API_READ_ARGV(crypto_scalarmult_curve25519, base);
	size_t bytes;
	unsigned char *q;

	bytes = crypto_scalarmult_curve25519_bytes();
	q = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

	if (q == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_scalarmult_curve25519_base(q, argv->n);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(q), bytes,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(q);
}
