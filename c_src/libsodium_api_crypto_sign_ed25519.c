// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libsodium_api_crypto_sign_ed25519.h"

static void	LS_API_EXEC(crypto_sign_ed25519, bytes);
static void	LS_API_EXEC(crypto_sign_ed25519, seedbytes);
static void	LS_API_EXEC(crypto_sign_ed25519, publickeybytes);
static void	LS_API_EXEC(crypto_sign_ed25519, secretkeybytes);
static int	LS_API_INIT(crypto_sign_ed25519, crypto_sign_ed25519);
static void	LS_API_EXEC(crypto_sign_ed25519, crypto_sign_ed25519);
static int	LS_API_INIT(crypto_sign_ed25519, open);
static void	LS_API_EXEC(crypto_sign_ed25519, open);
static int	LS_API_INIT(crypto_sign_ed25519, detached);
static void	LS_API_EXEC(crypto_sign_ed25519, detached);
static int	LS_API_INIT(crypto_sign_ed25519, verify_detached);
static void	LS_API_EXEC(crypto_sign_ed25519, verify_detached);
static void	LS_API_EXEC(crypto_sign_ed25519, keypair);
static int	LS_API_INIT(crypto_sign_ed25519, seed_keypair);
static void	LS_API_EXEC(crypto_sign_ed25519, seed_keypair);
static int	LS_API_INIT(crypto_sign_ed25519, pk_to_curve25519);
static void	LS_API_EXEC(crypto_sign_ed25519, pk_to_curve25519);
static int	LS_API_INIT(crypto_sign_ed25519, sk_to_curve25519);
static void	LS_API_EXEC(crypto_sign_ed25519, sk_to_curve25519);
static int	LS_API_INIT(crypto_sign_ed25519, sk_to_seed);
static void	LS_API_EXEC(crypto_sign_ed25519, sk_to_seed);
static int	LS_API_INIT(crypto_sign_ed25519, sk_to_pk);
static void	LS_API_EXEC(crypto_sign_ed25519, sk_to_pk);

libsodium_function_t	libsodium_functions_crypto_sign_ed25519[] = {
	LS_API_R_ARG0(crypto_sign_ed25519, bytes),
	LS_API_R_ARG0(crypto_sign_ed25519, seedbytes),
	LS_API_R_ARG0(crypto_sign_ed25519, publickeybytes),
	LS_API_R_ARG0(crypto_sign_ed25519, secretkeybytes),
	LS_API_R_ARGV(crypto_sign_ed25519, crypto_sign_ed25519, 2),
	LS_API_R_ARGV(crypto_sign_ed25519, open, 2),
	LS_API_R_ARGV(crypto_sign_ed25519, detached, 2),
	LS_API_R_ARGV(crypto_sign_ed25519, verify_detached, 3),
	LS_API_R_ARG0(crypto_sign_ed25519, keypair),
	LS_API_R_ARGV(crypto_sign_ed25519, seed_keypair, 1),
	LS_API_R_ARGV(crypto_sign_ed25519, pk_to_curve25519, 1),
	LS_API_R_ARGV(crypto_sign_ed25519, sk_to_curve25519, 1),
	LS_API_R_ARGV(crypto_sign_ed25519, sk_to_seed, 1),
	LS_API_R_ARGV(crypto_sign_ed25519, sk_to_pk, 1),
	{NULL}
};

/* crypto_sign_ed25519_bytes/0 */

static void
LS_API_EXEC(crypto_sign_ed25519, bytes)
{
	size_t bytes;

	bytes = crypto_sign_ed25519_bytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(bytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_ed25519_seedbytes/0 */

static void
LS_API_EXEC(crypto_sign_ed25519, seedbytes)
{
	size_t seedbytes;

	seedbytes = crypto_sign_ed25519_seedbytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(seedbytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_ed25519_publickeybytes/0 */

static void
LS_API_EXEC(crypto_sign_ed25519, publickeybytes)
{
	size_t publickeybytes;

	publickeybytes = crypto_sign_ed25519_publickeybytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(publickeybytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_ed25519_secretkeybytes/0 */

static void
LS_API_EXEC(crypto_sign_ed25519, secretkeybytes)
{
	size_t secretkeybytes;

	secretkeybytes = crypto_sign_ed25519_secretkeybytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(secretkeybytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_ed25519_crypto_sign_ed25519/2 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, crypto_sign_ed25519) {
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519);

static int
LS_API_INIT(crypto_sign_ed25519, crypto_sign_ed25519)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519) *argv;
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

	secretkeybytes = crypto_sign_ed25519_secretkeybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != secretkeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(mlen + secretkeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519)));
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
LS_API_EXEC(crypto_sign_ed25519, crypto_sign_ed25519)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, crypto_sign_ed25519) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, crypto_sign_ed25519);
	size_t bytes;
	unsigned char *sm;
	unsigned long long smlen;

	bytes = crypto_sign_ed25519_bytes();
	sm = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes + argv->mlen)));

	if (sm == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_sign_ed25519(sm, &smlen, argv->m, argv->mlen, argv->sk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(sm), smlen,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(sm);
}

/* crypto_sign_ed25519_open/2 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, open) {
	const unsigned char	*sm;
	unsigned long long	smlen;
	const unsigned char	*pk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, open);

static int
LS_API_INIT(crypto_sign_ed25519, open)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, open) *argv;
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

	publickeybytes = crypto_sign_ed25519_publickeybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != publickeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(smlen + publickeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, open))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, open) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, open)));
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
LS_API_EXEC(crypto_sign_ed25519, open)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, open) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, open);
	size_t bytes;
	unsigned char *m;
	unsigned long long mlen;
	int r;

	bytes = crypto_sign_ed25519_bytes();
	m = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->smlen - bytes)));

	if (m == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	r = crypto_sign_ed25519_open(m, &mlen, argv->sm, argv->smlen, argv->pk);

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

/* crypto_sign_ed25519_detached/2 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, detached) {
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, detached);

static int
LS_API_INIT(crypto_sign_ed25519, detached)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, detached) *argv;
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

	secretkeybytes = crypto_sign_ed25519_secretkeybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != secretkeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(mlen + secretkeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, detached))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, detached) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, detached)));
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
LS_API_EXEC(crypto_sign_ed25519, detached)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, detached) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, detached);
	size_t bytes;
	unsigned char *sig;
	unsigned long long siglen;
	int r;

	bytes = crypto_sign_ed25519_bytes();
	sig = (unsigned char *)(driver_alloc((ErlDrvSizeT)(bytes)));

	if (sig == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	r = crypto_sign_ed25519_detached(sig, &siglen, argv->m, argv->mlen, argv->sk);

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

/* crypto_sign_ed25519_verify_detached/3 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, verify_detached) {
	const unsigned char	*sig;
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*pk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached);

static int
LS_API_INIT(crypto_sign_ed25519, verify_detached)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached) *argv;
	int skip;
	int type;
	int type_length;
	size_t bytes;
	unsigned long long mlen;
	size_t publickeybytes;
	ErlDrvSizeT x;
	void *p;

	bytes = crypto_sign_ed25519_bytes();

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

	publickeybytes = crypto_sign_ed25519_publickeybytes();

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != publickeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(bytes + mlen + publickeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached)));
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
LS_API_EXEC(crypto_sign_ed25519, verify_detached)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, verify_detached) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, verify_detached);
	int r;

	r = crypto_sign_ed25519_verify_detached(argv->sig, argv->m, argv->mlen, argv->pk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_INT, (ErlDrvSInt)(r),
		ERL_DRV_TUPLE, 2
	};
	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_sign_ed25519_keypair/1 */

static void
LS_API_EXEC(crypto_sign_ed25519, keypair)
{
	size_t publickeybytes;
	size_t secretkeybytes;
	void *p;
	unsigned char *pk;
	unsigned char *sk;

	publickeybytes = crypto_sign_ed25519_publickeybytes();
	secretkeybytes = crypto_sign_ed25519_secretkeybytes();

	p = (void *)(driver_alloc((ErlDrvSizeT)(publickeybytes + secretkeybytes)));

	if (p == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	pk = (unsigned char *)(p);
	sk = (unsigned char *)(p + publickeybytes);

	(void) crypto_sign_ed25519_keypair(pk, sk);

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

/* crypto_sign_ed25519_seed_keypair/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, seed_keypair) {
	const unsigned char	*seed;
} LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair);

static int
LS_API_INIT(crypto_sign_ed25519, seed_keypair)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair) *argv;
	int type;
	int type_length;
	size_t seedbytes;
	ErlDrvSizeT x;
	void *p;

	seedbytes = crypto_sign_ed25519_seedbytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != seedbytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(seedbytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair)));
	argv->seed = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->seed), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, seed_keypair)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, seed_keypair) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, seed_keypair);
	size_t publickeybytes;
	size_t secretkeybytes;
	void *p;
	unsigned char *pk;
	unsigned char *sk;

	publickeybytes = crypto_sign_ed25519_publickeybytes();
	secretkeybytes = crypto_sign_ed25519_secretkeybytes();

	p = (void *)(driver_alloc((ErlDrvSizeT)(publickeybytes + secretkeybytes)));

	if (p == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	pk = (unsigned char *)(p);
	sk = (unsigned char *)(p + publickeybytes);

	(void) crypto_sign_ed25519_seed_keypair(pk, sk, argv->seed);

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

/* crypto_sign_ed25519_pk_to_curve25519/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, pk_to_curve25519) {
	const unsigned char	*ed25519_pk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519);

static int
LS_API_INIT(crypto_sign_ed25519, pk_to_curve25519)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519) *argv;
	int type;
	int type_length;
	size_t publickeybytes;
	ErlDrvSizeT x;
	void *p;

	publickeybytes = crypto_sign_ed25519_publickeybytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != publickeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(publickeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519)));
	argv->ed25519_pk = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->ed25519_pk), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, pk_to_curve25519)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, pk_to_curve25519) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, pk_to_curve25519);
	size_t curve25519_bytes;
	unsigned char *curve25519_pk;

	curve25519_bytes = crypto_scalarmult_curve25519_bytes();
	curve25519_pk = (void *)(driver_alloc((ErlDrvSizeT)(curve25519_bytes)));

	if (curve25519_pk == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, argv->ed25519_pk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(curve25519_pk), curve25519_bytes,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(curve25519_pk);
}

/* crypto_sign_ed25519_sk_to_curve25519/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, sk_to_curve25519) {
	const unsigned char	*ed25519_sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519);

static int
LS_API_INIT(crypto_sign_ed25519, sk_to_curve25519)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519) *argv;
	int type;
	int type_length;
	size_t secretkeybytes;
	ErlDrvSizeT x;
	void *p;

	secretkeybytes = crypto_sign_ed25519_secretkeybytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != secretkeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(secretkeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519)));
	argv->ed25519_sk = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->ed25519_sk), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, sk_to_curve25519)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_curve25519) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, sk_to_curve25519);
	size_t curve25519_bytes;
	unsigned char *curve25519_sk;

	curve25519_bytes = crypto_scalarmult_curve25519_bytes();
	curve25519_sk = (void *)(driver_alloc((ErlDrvSizeT)(curve25519_bytes)));

	if (curve25519_sk == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, argv->ed25519_sk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(curve25519_sk), curve25519_bytes,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(curve25519_sk);
}

/* crypto_sign_ed25519_sk_to_seed/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, sk_to_seed) {
	const unsigned char	*sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed);

static int
LS_API_INIT(crypto_sign_ed25519, sk_to_seed)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed) *argv;
	int type;
	int type_length;
	size_t secretkeybytes;
	ErlDrvSizeT x;
	void *p;

	secretkeybytes = crypto_sign_ed25519_secretkeybytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != secretkeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(secretkeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed)));
	argv->sk = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, sk_to_seed)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_seed) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, sk_to_seed);
	size_t seedbytes;
	unsigned char *seed;

	seedbytes = crypto_sign_ed25519_seedbytes();
	seed = (void *)(driver_alloc((ErlDrvSizeT)(seedbytes)));

	if (seed == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_sign_ed25519_sk_to_seed(seed, argv->sk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(seed), seedbytes,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(seed);
}

/* crypto_sign_ed25519_sk_to_pk/1 */

typedef struct LS_API_F_ARGV(crypto_sign_ed25519, sk_to_pk) {
	const unsigned char	*sk;
} LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk);

static int
LS_API_INIT(crypto_sign_ed25519, sk_to_pk)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk) *argv;
	int type;
	int type_length;
	size_t secretkeybytes;
	ErlDrvSizeT x;
	void *p;

	secretkeybytes = crypto_sign_ed25519_secretkeybytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != secretkeybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(secretkeybytes + (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk)));
	argv->sk = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->sk), NULL) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	request->argv = (void *)(argv);

	return 0;
}

static void
LS_API_EXEC(crypto_sign_ed25519, sk_to_pk)
{
	LS_API_F_ARGV_T(crypto_sign_ed25519, sk_to_pk) *argv;
	LS_API_READ_ARGV(crypto_sign_ed25519, sk_to_pk);
	size_t publickeybytes;
	unsigned char *pk;

	publickeybytes = crypto_sign_ed25519_publickeybytes();
	pk = (void *)(driver_alloc((ErlDrvSizeT)(publickeybytes)));

	if (pk == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_sign_ed25519_sk_to_pk(pk, argv->sk);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(pk), publickeybytes,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(pk);
}
