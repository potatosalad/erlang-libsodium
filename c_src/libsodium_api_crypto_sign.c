// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libsodium_api_crypto_sign.h"

static void	LS_API_EXEC(crypto_sign, bytes);
static void	LS_API_EXEC(crypto_sign, seedbytes);
static void	LS_API_EXEC(crypto_sign, publickeybytes);
static void	LS_API_EXEC(crypto_sign, secretkeybytes);
static void	LS_API_EXEC(crypto_sign, primitive);
static int	LS_API_INIT(crypto_sign, seed_keypair);
static void	LS_API_EXEC(crypto_sign, seed_keypair);
static void	LS_API_EXEC(crypto_sign, keypair);
static int	LS_API_INIT(crypto_sign, crypto_sign);
static void	LS_API_EXEC(crypto_sign, crypto_sign);
static int	LS_API_INIT(crypto_sign, open);
static void	LS_API_EXEC(crypto_sign, open);
static int	LS_API_INIT(crypto_sign, detached);
static void	LS_API_EXEC(crypto_sign, detached);
static int	LS_API_INIT(crypto_sign, verify_detached);
static void	LS_API_EXEC(crypto_sign, verify_detached);

libsodium_function_t	libsodium_functions_crypto_sign[] = {
	LS_API_R_ARG0(crypto_sign, bytes),
	LS_API_R_ARG0(crypto_sign, seedbytes),
	LS_API_R_ARG0(crypto_sign, publickeybytes),
	LS_API_R_ARG0(crypto_sign, secretkeybytes),
	LS_API_R_ARG0(crypto_sign, primitive),
	LS_API_R_ARGV(crypto_sign, seed_keypair, 1),
	LS_API_R_ARG0(crypto_sign, keypair),
	LS_API_R_ARGV(crypto_sign, crypto_sign, 2),
	LS_API_R_ARGV(crypto_sign, open, 2),
	LS_API_R_ARGV(crypto_sign, detached, 2),
	LS_API_R_ARGV(crypto_sign, verify_detached, 3),
	{NULL}
};

/* crypto_sign_bytes/0 */

static void
LS_API_EXEC(crypto_sign, bytes)
{
	size_t bytes;

	bytes = crypto_sign_bytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(bytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_seedbytes/0 */

static void
LS_API_EXEC(crypto_sign, seedbytes)
{
	size_t seedbytes;

	seedbytes = crypto_sign_seedbytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(seedbytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_publickeybytes/0 */

static void
LS_API_EXEC(crypto_sign, publickeybytes)
{
	size_t publickeybytes;

	publickeybytes = crypto_sign_publickeybytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(publickeybytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_secretkeybytes/0 */

static void
LS_API_EXEC(crypto_sign, secretkeybytes)
{
	size_t secretkeybytes;

	secretkeybytes = crypto_sign_secretkeybytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(secretkeybytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_primitive/0 */

static void
LS_API_EXEC(crypto_sign, primitive)
{
	const char *primitive;

	primitive = crypto_sign_primitive();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_ATOM, driver_mk_atom((char *)(primitive)),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_seed_keypair/1 */

typedef struct LS_API_F_ARGV(crypto_sign, seed_keypair) {
	const unsigned char	*seed;
} LS_API_F_ARGV_T(crypto_sign, seed_keypair);

static int
LS_API_INIT(crypto_sign, seed_keypair)
{
	LS_API_F_ARGV_T(crypto_sign, seed_keypair) *argv;
	int type;
	int type_length;
	size_t seedbytes;
	ErlDrvSizeT x;
	void *p;

	seedbytes = crypto_sign_seedbytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != seedbytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(seedbytes + (sizeof (LS_API_F_ARGV_T(crypto_sign, seed_keypair))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign, seed_keypair) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign, seed_keypair)));
	argv->seed = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->seed), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign, seed_keypair)
{
	LS_API_F_ARGV_T(crypto_sign, seed_keypair) *argv;
	LS_API_READ_ARGV(crypto_sign, seed_keypair);
	size_t publickeybytes;
	size_t secretkeybytes;
	void *p;
	unsigned char *pk;
	unsigned char *sk;

	publickeybytes = crypto_sign_publickeybytes();
	secretkeybytes = crypto_sign_secretkeybytes();

	p = (void *)(driver_alloc((ErlDrvSizeT)(publickeybytes + secretkeybytes)));

	if (p == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	pk = (unsigned char *)(p);
	sk = (unsigned char *)(p + publickeybytes);

	(void) crypto_sign_seed_keypair(pk, sk, argv->seed);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes,
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sk), secretkeybytes,
		ERL_DRV_TUPLE, 2,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(p);
}

/* crypto_sign_keypair/1 */

static void
LS_API_EXEC(crypto_sign, keypair)
{
	size_t publickeybytes;
	size_t secretkeybytes;
	void *p;
	unsigned char *pk;
	unsigned char *sk;

	publickeybytes = crypto_sign_publickeybytes();
	secretkeybytes = crypto_sign_secretkeybytes();

	p = (void *)(driver_alloc((ErlDrvSizeT)(publickeybytes + secretkeybytes)));

	if (p == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	pk = (unsigned char *)(p);
	sk = (unsigned char *)(p + publickeybytes);

	(void) crypto_sign_keypair(pk, sk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes,
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sk), secretkeybytes,
		ERL_DRV_TUPLE, 2,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(p);
}

/* crypto_sign_crypto_sign/2 */

typedef struct LS_API_F_ARGV(crypto_sign, crypto_sign) {
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*sk;
} LS_API_F_ARGV_T(crypto_sign, crypto_sign);

static int
LS_API_INIT(crypto_sign, crypto_sign)
{
	LS_API_F_ARGV_T(crypto_sign, crypto_sign) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long mlen;
	size_t secretkeybytes;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	mlen = (unsigned long long)(type_length);

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	secretkeybytes = crypto_sign_secretkeybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != secretkeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(mlen + secretkeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign, crypto_sign))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign, crypto_sign) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign, crypto_sign)));
	argv->m = (const unsigned char *)(p);
	p += mlen;
	argv->sk = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign, crypto_sign)
{
	LS_API_F_ARGV_T(crypto_sign, crypto_sign) *argv;
	LS_API_READ_ARGV(crypto_sign, crypto_sign);
	size_t bytes;
	unsigned char *sm;
	unsigned long long smlen;

	bytes = crypto_sign_bytes();
	sm = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes + argv->mlen)));

	if (sm == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_sign(sm, &smlen, argv->m, argv->mlen, argv->sk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sm), smlen,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(sm);
}

/* crypto_sign_open/2 */

typedef struct LS_API_F_ARGV(crypto_sign, open) {
	const unsigned char	*sm;
	unsigned long long	smlen;
	const unsigned char	*pk;
} LS_API_F_ARGV_T(crypto_sign, open);

static int
LS_API_INIT(crypto_sign, open)
{
	LS_API_F_ARGV_T(crypto_sign, open) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long smlen;
	size_t publickeybytes;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	smlen = (unsigned long long)(type_length);

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	publickeybytes = crypto_sign_publickeybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != publickeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(smlen + publickeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign, open))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign, open) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign, open)));
	argv->sm = (const unsigned char *)(p);
	p += smlen;
	argv->pk = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->sm), (long *)&(argv->smlen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->pk), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign, open)
{
	LS_API_F_ARGV_T(crypto_sign, open) *argv;
	LS_API_READ_ARGV(crypto_sign, open);
	size_t bytes;
	unsigned char *m;
	unsigned long long mlen;
	int r;

	bytes = crypto_sign_bytes();
	m = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->smlen - bytes)));

	if (m == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	r = crypto_sign_open(m, &mlen, argv->sm, argv->smlen, argv->pk);

	if (r == 0) {
		ErlDrvTermData spec[] = {
			LS_RES_TAG(request),
			ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen,
			ERL_DRV_TUPLE, 2
		};
		LS_RESPOND(request, spec, __FILE__, __LINE__);
	} else {
		ErlDrvTermData spec[] = {
			LS_RES_TAG(request),
			ERL_DRV_INT, (ErlDrvSInt)(r),
			ERL_DRV_TUPLE, 2
		};
		LS_RESPOND(request, spec, __FILE__, __LINE__);
	}

	(void) driver_free(m);
}

/* crypto_sign_detached/2 */

typedef struct LS_API_F_ARGV(crypto_sign, detached) {
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*sk;
} LS_API_F_ARGV_T(crypto_sign, detached);

static int
LS_API_INIT(crypto_sign, detached)
{
	LS_API_F_ARGV_T(crypto_sign, detached) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long mlen;
	size_t secretkeybytes;
	ErlDrvSizeT x;
	void *p;

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	mlen = (unsigned long long)(type_length);

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	secretkeybytes = crypto_sign_secretkeybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != secretkeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(mlen + secretkeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign, detached))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign, detached) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign, detached)));
	argv->m = (const unsigned char *)(p);
	p += mlen;
	argv->sk = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign, detached)
{
	LS_API_F_ARGV_T(crypto_sign, detached) *argv;
	LS_API_READ_ARGV(crypto_sign, detached);
	size_t bytes;
	unsigned char *sig;
	unsigned long long siglen;
	int r;

	bytes = crypto_sign_bytes();
	sig = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

	if (sig == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	r = crypto_sign_detached(sig, &siglen, argv->m, argv->mlen, argv->sk);

	if (r == 0) {
		ErlDrvTermData spec[] = {
			LS_RES_TAG(request),
			ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sig), siglen,
			ERL_DRV_TUPLE, 2
		};
		LS_RESPOND(request, spec, __FILE__, __LINE__);
	} else {
		ErlDrvTermData spec[] = {
			LS_RES_TAG(request),
			ERL_DRV_INT, (ErlDrvSInt)(r),
			ERL_DRV_TUPLE, 2
		};
		LS_RESPOND(request, spec, __FILE__, __LINE__);
	}

	(void) driver_free(sig);
}

/* crypto_sign_verify_detached/3 */

typedef struct LS_API_F_ARGV(crypto_sign, verify_detached) {
	const unsigned char	*sig;
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*pk;
} LS_API_F_ARGV_T(crypto_sign, verify_detached);

static int
LS_API_INIT(crypto_sign, verify_detached)
{
	LS_API_F_ARGV_T(crypto_sign, verify_detached) *argv;
	int skip;
	int type;
	int type_length;
	size_t bytes;
	unsigned long long mlen;
	size_t publickeybytes;
	ErlDrvSizeT x;
	void *p;

	bytes = crypto_sign_bytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != bytes) {
		return -1;
	}

	skip = *index;

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	mlen = (unsigned long long)(type_length);

	publickeybytes = crypto_sign_publickeybytes();

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != publickeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(bytes + mlen + publickeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign, verify_detached))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign, verify_detached) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign, verify_detached)));
	argv->sig = (const unsigned char *)(p);
	p += bytes;
	argv->m = (const unsigned char *)(p);
	p += mlen;
	argv->pk = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->sig), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->pk), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign, verify_detached)
{
	LS_API_F_ARGV_T(crypto_sign, verify_detached) *argv;
	LS_API_READ_ARGV(crypto_sign, verify_detached);
	int r;

	r = crypto_sign_verify_detached(argv->sig, argv->m, argv->mlen, argv->pk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_INT, (ErlDrvSInt)(r),
		ERL_DRV_TUPLE, 2
	};
	LS_RESPOND(request, spec, __FILE__, __LINE__);
}
