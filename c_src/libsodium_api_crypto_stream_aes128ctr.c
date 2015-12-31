// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libsodium_api_crypto_stream_aes128ctr.h"

static void	LS_API_EXEC(crypto_stream_aes128ctr, keybytes);
static void	LS_API_EXEC(crypto_stream_aes128ctr, noncebytes);
static void	LS_API_EXEC(crypto_stream_aes128ctr, beforenmbytes);
static int	LS_API_INIT(crypto_stream_aes128ctr, crypto_stream_aes128ctr);
static void	LS_API_EXEC(crypto_stream_aes128ctr, crypto_stream_aes128ctr);
static int	LS_API_INIT(crypto_stream_aes128ctr, xor);
static void	LS_API_EXEC(crypto_stream_aes128ctr, xor);
static int	LS_API_INIT(crypto_stream_aes128ctr, beforenm);
static void	LS_API_EXEC(crypto_stream_aes128ctr, beforenm);
static int	LS_API_INIT(crypto_stream_aes128ctr, afternm);
static void	LS_API_EXEC(crypto_stream_aes128ctr, afternm);
static int	LS_API_INIT(crypto_stream_aes128ctr, xor_afternm);
static void	LS_API_EXEC(crypto_stream_aes128ctr, xor_afternm);

libsodium_function_t	libsodium_functions_crypto_stream_aes128ctr[] = {
	LS_API_R_ARG0(crypto_stream_aes128ctr, keybytes),
	LS_API_R_ARG0(crypto_stream_aes128ctr, noncebytes),
	LS_API_R_ARG0(crypto_stream_aes128ctr, beforenmbytes),
	LS_API_R_ARGV(crypto_stream_aes128ctr, crypto_stream_aes128ctr, 3),
	LS_API_R_ARGV(crypto_stream_aes128ctr, xor, 3),
	LS_API_R_ARGV(crypto_stream_aes128ctr, beforenm, 1),
	LS_API_R_ARGV(crypto_stream_aes128ctr, afternm, 3),
	LS_API_R_ARGV(crypto_stream_aes128ctr, xor_afternm, 3),
	{NULL}
};

/* crypto_stream_aes128ctr_keybytes/0 */

static void
LS_API_EXEC(crypto_stream_aes128ctr, keybytes)
{
	size_t keybytes;

	keybytes = crypto_stream_aes128ctr_keybytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(keybytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_aes128ctr_noncebytes/0 */

static void
LS_API_EXEC(crypto_stream_aes128ctr, noncebytes)
{
	size_t noncebytes;

	noncebytes = crypto_stream_aes128ctr_noncebytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(noncebytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_aes128ctr_beforenmbytes/0 */

static void
LS_API_EXEC(crypto_stream_aes128ctr, beforenmbytes)
{
	size_t beforenmbytes;

	beforenmbytes = crypto_stream_aes128ctr_beforenmbytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(beforenmbytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_aes128ctr_crypto_stream_aes128ctr/3 */

typedef struct LS_API_F_ARGV(crypto_stream_aes128ctr, crypto_stream_aes128ctr) {
	unsigned long long	outlen;
	const unsigned char	*n;
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_stream_aes128ctr, crypto_stream_aes128ctr);

static int
LS_API_INIT(crypto_stream_aes128ctr, crypto_stream_aes128ctr)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, crypto_stream_aes128ctr) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long outlen;
	size_t noncebytes;
	size_t keybytes;
	ErlDrvSizeT x;
	void *p;

	if (ei_decode_ulong(buffer, index, (unsigned long *)&(outlen)) < 0) {
		return -1;
	}

	noncebytes = crypto_stream_aes128ctr_noncebytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != noncebytes) {
		return -1;
	}

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	keybytes = crypto_stream_aes128ctr_keybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(noncebytes + keybytes + (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, crypto_stream_aes128ctr))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_stream_aes128ctr, crypto_stream_aes128ctr) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, crypto_stream_aes128ctr)));
	argv->outlen = outlen;
	argv->n = (const unsigned char *)(p);
	p += noncebytes;
	argv->k = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_stream_aes128ctr, crypto_stream_aes128ctr)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, crypto_stream_aes128ctr) *argv;
	LS_API_READ_ARGV(crypto_stream_aes128ctr, crypto_stream_aes128ctr);
	unsigned char *out;

	out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->outlen)));

	if (out == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_stream_aes128ctr(out, argv->outlen, argv->n, argv->k);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->outlen,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(out);
}

/* crypto_stream_aes128ctr_xor/3 */

typedef struct LS_API_F_ARGV(crypto_stream_aes128ctr, xor) {
	const unsigned char	*in;
	unsigned long long	inlen;
	const unsigned char	*n;
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor);

static int
LS_API_INIT(crypto_stream_aes128ctr, xor)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long inlen;
	size_t noncebytes;
	size_t keybytes;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	inlen = (unsigned long long)(type_length);

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	noncebytes = crypto_stream_aes128ctr_noncebytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != noncebytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	keybytes = crypto_stream_aes128ctr_keybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(inlen + noncebytes + keybytes + (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor)));
	argv->in = (const unsigned char *)(p);
	p += inlen;
	argv->n = (const unsigned char *)(p);
	p += noncebytes;
	argv->k = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->inlen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->n), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_stream_aes128ctr, xor)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor) *argv;
	LS_API_READ_ARGV(crypto_stream_aes128ctr, xor);
	unsigned char *out;

	out = (unsigned char *)(argv->in);

	(void) crypto_stream_aes128ctr_xor(out, argv->in, argv->inlen, argv->n, argv->k);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->inlen,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_stream_aes128ctr_beforenm/3 */

typedef struct LS_API_F_ARGV(crypto_stream_aes128ctr, beforenm) {
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_stream_aes128ctr, beforenm);

static int
LS_API_INIT(crypto_stream_aes128ctr, beforenm)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, beforenm) *argv;
	int type;
	int type_length;
	size_t keybytes;
	ErlDrvSizeT x;
	void *p;

	keybytes = crypto_stream_aes128ctr_keybytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(keybytes + (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, beforenm))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_stream_aes128ctr, beforenm) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, beforenm)));
	argv->k = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->k), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_stream_aes128ctr, beforenm)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, beforenm) *argv;
	LS_API_READ_ARGV(crypto_stream_aes128ctr, beforenm);
	size_t beforenmbytes;
	unsigned char *c;

	beforenmbytes = crypto_stream_aes128ctr_beforenmbytes();
	c = (unsigned char *)(driver_alloc((ErlDrvSizeT)(beforenmbytes)));

	if (c == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_stream_aes128ctr_beforenm(c, argv->k);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), beforenmbytes,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(c);
}

/* crypto_stream_aes128ctr_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_stream_aes128ctr, afternm) {
	unsigned long long	len;
	const unsigned char	*nonce;
	const unsigned char	*c;
} LS_API_F_ARGV_T(crypto_stream_aes128ctr, afternm);

static int
LS_API_INIT(crypto_stream_aes128ctr, afternm)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, afternm) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long len;
	size_t noncebytes;
	size_t beforenmbytes;
	ErlDrvSizeT x;
	void *p;

	if (ei_decode_ulong(buffer, index, (unsigned long *)&(len)) < 0) {
		return -1;
	}

	noncebytes = crypto_stream_aes128ctr_noncebytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != noncebytes) {
		return -1;
	}

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	beforenmbytes = crypto_stream_aes128ctr_beforenmbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != beforenmbytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(noncebytes + beforenmbytes + (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, afternm))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_stream_aes128ctr, afternm) *)(p);
	argv->len = len;
	p += (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, afternm)));
	argv->nonce = (const unsigned char *)(p);
	p += noncebytes;
	argv->c = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->nonce), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->c), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_stream_aes128ctr, afternm)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, afternm) *argv;
	LS_API_READ_ARGV(crypto_stream_aes128ctr, afternm);
	unsigned char *out;

	out = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->len)));

	if (out == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_stream_aes128ctr_afternm(out, argv->len, argv->nonce, argv->c);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->len,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(out);
}

/* crypto_stream_aes128ctr_xor_afternm/3 */

typedef struct LS_API_F_ARGV(crypto_stream_aes128ctr, xor_afternm) {
	const unsigned char	*in;
	unsigned long long	len;
	const unsigned char	*nonce;
	const unsigned char	*c;
} LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor_afternm);

static int
LS_API_INIT(crypto_stream_aes128ctr, xor_afternm)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor_afternm) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long len;
	size_t noncebytes;
	size_t beforenmbytes;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	len = (unsigned long long)(type_length);

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	noncebytes = crypto_stream_aes128ctr_noncebytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != noncebytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	beforenmbytes = crypto_stream_aes128ctr_beforenmbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != beforenmbytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(noncebytes + beforenmbytes + (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor_afternm))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor_afternm) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor_afternm)));
	argv->in = (const unsigned char *)(p);
	p += len;
	argv->nonce = (const unsigned char *)(p);
	p += noncebytes;
	argv->c = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->in), (long *)&(argv->len)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->nonce), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->c), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_stream_aes128ctr, xor_afternm)
{
	LS_API_F_ARGV_T(crypto_stream_aes128ctr, xor_afternm) *argv;
	LS_API_READ_ARGV(crypto_stream_aes128ctr, xor_afternm);
	unsigned char *out;

	out = (unsigned char *)(argv->in);

	(void) crypto_stream_aes128ctr_xor_afternm(out, argv->in, argv->len, argv->nonce, argv->c);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(out), argv->len,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}
