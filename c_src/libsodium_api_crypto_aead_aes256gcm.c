// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libsodium_api_crypto_aead_aes256gcm.h"

static void	LS_API_EXEC(crypto_aead_aes256gcm, is_available);
static void	LS_API_EXEC(crypto_aead_aes256gcm, keybytes);
static void	LS_API_EXEC(crypto_aead_aes256gcm, nsecbytes);
static void	LS_API_EXEC(crypto_aead_aes256gcm, npubbytes);
static void	LS_API_EXEC(crypto_aead_aes256gcm, abytes);
static void	LS_API_EXEC(crypto_aead_aes256gcm, statebytes);
static int	LS_API_INIT(crypto_aead_aes256gcm, encrypt);
static void	LS_API_EXEC(crypto_aead_aes256gcm, encrypt);
static int	LS_API_INIT(crypto_aead_aes256gcm, decrypt);
static void	LS_API_EXEC(crypto_aead_aes256gcm, decrypt);
// static int	LS_API_INIT(crypto_aead_aes256gcm, beforenm);
// static void	LS_API_EXEC(crypto_aead_aes256gcm, beforenm);
// static int	LS_API_INIT(crypto_aead_aes256gcm, encrypt_afternm);
// static void	LS_API_EXEC(crypto_aead_aes256gcm, encrypt_afternm);
// static int	LS_API_INIT(crypto_aead_aes256gcm, decrypt_afternm);
// static void	LS_API_EXEC(crypto_aead_aes256gcm, decrypt_afternm);

libsodium_function_t	libsodium_functions_crypto_aead_aes256gcm[] = {
	LS_API_R_ARG0(crypto_aead_aes256gcm, is_available),
	LS_API_R_ARG0(crypto_aead_aes256gcm, keybytes),
	LS_API_R_ARG0(crypto_aead_aes256gcm, nsecbytes),
	LS_API_R_ARG0(crypto_aead_aes256gcm, npubbytes),
	LS_API_R_ARG0(crypto_aead_aes256gcm, abytes),
	LS_API_R_ARG0(crypto_aead_aes256gcm, statebytes),
	LS_API_R_ARGV(crypto_aead_aes256gcm, encrypt, 5),
	LS_API_R_ARGV(crypto_aead_aes256gcm, decrypt, 5),
	// LS_API_R_ARGV(crypto_aead_aes256gcm, beforenm, 1),
	// LS_API_R_ARGV(crypto_aead_aes256gcm, encrypt_afternm, 5),
	// LS_API_R_ARGV(crypto_aead_aes256gcm, decrypt_afternm, 5),
	{NULL}
};

/* crypto_aead_aes256gcm_is_available/0 */

static void
LS_API_EXEC(crypto_aead_aes256gcm, is_available)
{
	int is_available;

	is_available = crypto_aead_aes256gcm_is_available();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_INT, (ErlDrvSInt)(is_available),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_aead_aes256gcm_keybytes/0 */

static void
LS_API_EXEC(crypto_aead_aes256gcm, keybytes)
{
	size_t keybytes;

	keybytes = crypto_aead_aes256gcm_keybytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(keybytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_aead_aes256gcm_nsecbytes/0 */

static void
LS_API_EXEC(crypto_aead_aes256gcm, nsecbytes)
{
	size_t nsecbytes;

	nsecbytes = crypto_aead_aes256gcm_nsecbytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(nsecbytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_aead_aes256gcm_npubbytes/0 */

static void
LS_API_EXEC(crypto_aead_aes256gcm, npubbytes)
{
	size_t npubbytes;

	npubbytes = crypto_aead_aes256gcm_npubbytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(npubbytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_aead_aes256gcm_abytes/0 */

static void
LS_API_EXEC(crypto_aead_aes256gcm, abytes)
{
	size_t abytes;

	abytes = crypto_aead_aes256gcm_abytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(abytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_aead_aes256gcm_statebytes/0 */

static void
LS_API_EXEC(crypto_aead_aes256gcm, statebytes)
{
	size_t statebytes;

	statebytes = crypto_aead_aes256gcm_statebytes();

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_UINT, (ErlDrvUInt)(statebytes),
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* crypto_aead_aes256gcm_encrypt/5 */

typedef struct LS_API_F_ARGV(crypto_aead_aes256gcm, encrypt) {
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*ad;
	unsigned long long	adlen;
	const unsigned char	*nsec;
	const unsigned char	*npub;
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_aead_aes256gcm, encrypt);

static int
LS_API_INIT(crypto_aead_aes256gcm, encrypt)
{
	LS_API_F_ARGV_T(crypto_aead_aes256gcm, encrypt) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long mlen;
	unsigned long long adlen;
	size_t nsecbytes;
	size_t npubbytes;
	size_t keybytes;
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

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	adlen = (unsigned long long)(type_length);

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	nsecbytes = crypto_aead_aes256gcm_nsecbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != nsecbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	npubbytes = crypto_aead_aes256gcm_npubbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != npubbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	keybytes = crypto_aead_aes256gcm_keybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(mlen + adlen + nsecbytes + npubbytes + keybytes + (sizeof (LS_API_F_ARGV_T(crypto_aead_aes256gcm, encrypt))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_aead_aes256gcm, encrypt) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_aead_aes256gcm, encrypt)));
	argv->m = (const unsigned char *)(p);
	p += mlen;
	if (adlen == 0) {
		argv->ad = NULL;
		argv->adlen = 0;
	} else {
		argv->ad = (const unsigned char *)(p);
		p += adlen;
	}
	if (nsecbytes == 0) {
		argv->nsec = NULL;
	} else {
		argv->nsec = (const unsigned char *)(p);
		p += nsecbytes;
	}
	argv->npub = (const unsigned char *)(p);
	p += npubbytes;
	argv->k = (const unsigned char *)(p);

	if (ei_decode_binary(buffer, index, (void *)(argv->m), (long *)&(argv->mlen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (adlen == 0) {
		if (ei_skip_term(buffer, index) < 0) {
			(void) driver_free(argv);
			return -1;
		}
	} else {
		if (ei_decode_binary(buffer, index, (void *)(argv->ad), (long *)&(argv->adlen)) < 0) {
			(void) driver_free(argv);
			return -1;
		}
	}

	if (nsecbytes == 0) {
		if (ei_skip_term(buffer, index) < 0) {
			(void) driver_free(argv);
			return -1;
		}
	} else {
		if (ei_decode_binary(buffer, index, (void *)(argv->nsec), NULL) < 0) {
			(void) driver_free(argv);
			return -1;
		}
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->npub), NULL) < 0) {
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
LS_API_EXEC(crypto_aead_aes256gcm, encrypt)
{
	LS_API_F_ARGV_T(crypto_aead_aes256gcm, encrypt) *argv;
	LS_API_READ_ARGV(crypto_aead_aes256gcm, encrypt);
	size_t abytes;
	unsigned char *c;
	unsigned long long clen;

	abytes = crypto_aead_aes256gcm_abytes();
	c = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->mlen + abytes)));

	if (c == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	(void) crypto_aead_aes256gcm_encrypt(c, &clen, argv->m, argv->mlen, argv->ad, argv->adlen, argv->nsec, argv->npub, argv->k);

	ErlDrvTermData spec[] = {
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen,
		ERL_DRV_TUPLE, 2
	};

	LS_RESPOND(request, spec, __FILE__, __LINE__);

	(void) driver_free(c);
}

/* crypto_aead_aes256gcm_decrypt/5 */

typedef struct LS_API_F_ARGV(crypto_aead_aes256gcm, decrypt) {
	unsigned char		*nsec;
	const unsigned char	*c;
	unsigned long long	clen;
	const unsigned char	*ad;
	unsigned long long	adlen;
	const unsigned char	*npub;
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_aead_aes256gcm, decrypt);

static int
LS_API_INIT(crypto_aead_aes256gcm, decrypt)
{
	LS_API_F_ARGV_T(crypto_aead_aes256gcm, decrypt) *argv;
	int skip;
	int type;
	int type_length;
	size_t nsecbytes;
	unsigned long long clen;
	unsigned long long adlen;
	size_t npubbytes;
	size_t keybytes;
	ErlDrvSizeT x;
	void *p;

	nsecbytes = crypto_aead_aes256gcm_nsecbytes();

	if (ei_get_type(buffer, index, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != nsecbytes) {
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

	clen = (unsigned long long)(type_length);

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT) {
		return -1;
	}

	adlen = (unsigned long long)(type_length);

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	npubbytes = crypto_aead_aes256gcm_npubbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != npubbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	keybytes = crypto_aead_aes256gcm_keybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(nsecbytes + clen + adlen + npubbytes + keybytes + (sizeof (LS_API_F_ARGV_T(crypto_aead_aes256gcm, decrypt))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_aead_aes256gcm, decrypt) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_aead_aes256gcm, decrypt)));
	if (nsecbytes == 0) {
		argv->nsec = NULL;
	} else {
		argv->nsec = (unsigned char *)(p);
		p += nsecbytes;
	}
	argv->c = (const unsigned char *)(p);
	p += clen;
	if (adlen == 0) {
		argv->ad = NULL;
		argv->adlen = 0;
	} else {
		argv->ad = (const unsigned char *)(p);
		p += adlen;
	}
	argv->npub = (const unsigned char *)(p);
	p += npubbytes;
	argv->k = (const unsigned char *)(p);

	if (nsecbytes == 0) {
		if (ei_skip_term(buffer, index) < 0) {
			(void) driver_free(argv);
			return -1;
		}
	} else {
		if (ei_decode_binary(buffer, index, (void *)(argv->nsec), NULL) < 0) {
			(void) driver_free(argv);
			return -1;
		}
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->c), (long *)&(argv->clen)) < 0) {
		(void) driver_free(argv);
		return -1;
	}

	if (adlen == 0) {
		if (ei_skip_term(buffer, index) < 0) {
			(void) driver_free(argv);
			return -1;
		}
	} else {
		if (ei_decode_binary(buffer, index, (void *)(argv->ad), (long *)&(argv->adlen)) < 0) {
			(void) driver_free(argv);
			return -1;
		}
	}

	if (ei_decode_binary(buffer, index, (void *)(argv->npub), NULL) < 0) {
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
LS_API_EXEC(crypto_aead_aes256gcm, decrypt)
{
	LS_API_F_ARGV_T(crypto_aead_aes256gcm, decrypt) *argv;
	LS_API_READ_ARGV(crypto_aead_aes256gcm, decrypt);
	size_t abytes;
	unsigned char *m;
	unsigned long long mlen;
	int r;

	abytes = crypto_aead_aes256gcm_abytes();
	m = (unsigned char *)(driver_alloc((ErlDrvSizeT)(argv->clen - abytes)));

	if (m == NULL) {
		LS_FAIL_OOM(request->port->drv_port);
		return;
	}

	r = crypto_aead_aes256gcm_decrypt(m, &mlen, argv->nsec, argv->c, argv->clen, argv->ad, argv->adlen, argv->npub, argv->k);

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
