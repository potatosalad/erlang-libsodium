// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "libsodium_api_crypto_aead_chacha20poly1305.h"

static void	LS_API_EXEC(crypto_aead_chacha20poly1305, keybytes);
static void	LS_API_EXEC(crypto_aead_chacha20poly1305, nsecbytes);
static void	LS_API_EXEC(crypto_aead_chacha20poly1305, npubbytes);
static void	LS_API_EXEC(crypto_aead_chacha20poly1305, abytes);
static int	LS_API_INIT(crypto_aead_chacha20poly1305, encrypt);
static void	LS_API_EXEC(crypto_aead_chacha20poly1305, encrypt);
static int	LS_API_INIT(crypto_aead_chacha20poly1305, decrypt);
static void	LS_API_EXEC(crypto_aead_chacha20poly1305, decrypt);
static void	LS_API_EXEC(crypto_aead_chacha20poly1305, ietf_npubbytes);
static int	LS_API_INIT(crypto_aead_chacha20poly1305, ietf_encrypt);
static void	LS_API_EXEC(crypto_aead_chacha20poly1305, ietf_encrypt);
static int	LS_API_INIT(crypto_aead_chacha20poly1305, ietf_decrypt);
static void	LS_API_EXEC(crypto_aead_chacha20poly1305, ietf_decrypt);

libsodium_function_t	libsodium_functions_crypto_aead_chacha20poly1305[] = {
	LS_API_R_ARG0(crypto_aead_chacha20poly1305, keybytes),
	LS_API_R_ARG0(crypto_aead_chacha20poly1305, nsecbytes),
	LS_API_R_ARG0(crypto_aead_chacha20poly1305, npubbytes),
	LS_API_R_ARG0(crypto_aead_chacha20poly1305, abytes),
	LS_API_R_ARGV(crypto_aead_chacha20poly1305, encrypt, 5),
	LS_API_R_ARGV(crypto_aead_chacha20poly1305, decrypt, 5),
	LS_API_R_ARG0(crypto_aead_chacha20poly1305, ietf_npubbytes),
	LS_API_R_ARGV(crypto_aead_chacha20poly1305, ietf_encrypt, 5),
	LS_API_R_ARGV(crypto_aead_chacha20poly1305, ietf_decrypt, 5),
	{NULL}
};

/* crypto_aead_chacha20poly1305_keybytes/0 */

LS_API_GET_SIZE(crypto_aead_chacha20poly1305, keybytes);

/* crypto_aead_chacha20poly1305_nsecbytes/0 */

LS_API_GET_SIZE(crypto_aead_chacha20poly1305, nsecbytes);

/* crypto_aead_chacha20poly1305_npubbytes/0 */

LS_API_GET_SIZE(crypto_aead_chacha20poly1305, npubbytes);

/* crypto_aead_chacha20poly1305_abytes/0 */

LS_API_GET_SIZE(crypto_aead_chacha20poly1305, abytes);

/* crypto_aead_chacha20poly1305_encrypt/5 */

typedef struct LS_API_F_ARGV(crypto_aead_chacha20poly1305, encrypt) {
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*ad;
	unsigned long long	adlen;
	const unsigned char	*nsec;
	const unsigned char	*npub;
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, encrypt);

static int
LS_API_INIT(crypto_aead_chacha20poly1305, encrypt)
{
	LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, encrypt) *argv;
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

	nsecbytes = crypto_aead_chacha20poly1305_nsecbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != nsecbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	npubbytes = crypto_aead_chacha20poly1305_npubbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != npubbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	keybytes = crypto_aead_chacha20poly1305_keybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(mlen + adlen + nsecbytes + npubbytes + keybytes + (sizeof (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, encrypt))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, encrypt) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, encrypt)));
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
LS_API_EXEC(crypto_aead_chacha20poly1305, encrypt)
{
	LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, encrypt) *argv;
	LS_API_READ_ARGV(crypto_aead_chacha20poly1305, encrypt);

	size_t abytes = crypto_aead_chacha20poly1305_abytes();
	size_t cbytes = argv->mlen + abytes;
	unsigned char c[cbytes];
	unsigned long long clen;

	LS_SAFE_REPLY(crypto_aead_chacha20poly1305_encrypt(c, &clen, argv->m, argv->mlen, argv->ad, argv->adlen, argv->nsec, argv->npub, argv->k), LS_PROTECT({
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen,
		ERL_DRV_TUPLE, 2
	}), __FILE__, __LINE__);

	(void) sodium_memzero(c, cbytes);
}

/* crypto_aead_chacha20poly1305_decrypt/5 */

typedef struct LS_API_F_ARGV(crypto_aead_chacha20poly1305, decrypt) {
	unsigned char		*nsec;
	const unsigned char	*c;
	unsigned long long	clen;
	const unsigned char	*ad;
	unsigned long long	adlen;
	const unsigned char	*npub;
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, decrypt);

static int
LS_API_INIT(crypto_aead_chacha20poly1305, decrypt)
{
	LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, decrypt) *argv;
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

	nsecbytes = crypto_aead_chacha20poly1305_nsecbytes();

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

	npubbytes = crypto_aead_chacha20poly1305_npubbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != npubbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	keybytes = crypto_aead_chacha20poly1305_keybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(nsecbytes + clen + adlen + npubbytes + keybytes + (sizeof (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, decrypt))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, decrypt) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, decrypt)));
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
LS_API_EXEC(crypto_aead_chacha20poly1305, decrypt)
{
	LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, decrypt) *argv;
	LS_API_READ_ARGV(crypto_aead_chacha20poly1305, decrypt);

	size_t abytes = crypto_aead_chacha20poly1305_abytes();
	size_t mbytes = (abytes > argv->clen) ? argv->clen : argv->clen - abytes;
	unsigned char m[mbytes];
	unsigned long long mlen;

	LS_SAFE_REPLY(crypto_aead_chacha20poly1305_decrypt(m, &mlen, argv->nsec, argv->c, argv->clen, argv->ad, argv->adlen, argv->npub, argv->k), LS_PROTECT({
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen,
		ERL_DRV_TUPLE, 2
	}), __FILE__, __LINE__);

	(void) sodium_memzero(m, mbytes);
}

/* crypto_aead_chacha20poly1305_ietf_npubbytes/0 */

LS_API_GET_SIZE(crypto_aead_chacha20poly1305, ietf_npubbytes);

/* crypto_aead_chacha20poly1305_ietf_encrypt/5 */

typedef struct LS_API_F_ARGV(crypto_aead_chacha20poly1305, ietf_encrypt) {
	const unsigned char	*m;
	unsigned long long	mlen;
	const unsigned char	*ad;
	unsigned long long	adlen;
	const unsigned char	*nsec;
	const unsigned char	*npub;
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_encrypt);

static int
LS_API_INIT(crypto_aead_chacha20poly1305, ietf_encrypt)
{
	LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_encrypt) *argv;
	int skip;
	int type;
	int type_length;
	unsigned long long mlen;
	unsigned long long adlen;
	size_t nsecbytes;
	size_t ietf_npubbytes;
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

	nsecbytes = crypto_aead_chacha20poly1305_nsecbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != nsecbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	ietf_npubbytes = crypto_aead_chacha20poly1305_ietf_npubbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != ietf_npubbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	keybytes = crypto_aead_chacha20poly1305_keybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(mlen + adlen + nsecbytes + ietf_npubbytes + keybytes + (sizeof (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_encrypt))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_encrypt) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_encrypt)));
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
	p += ietf_npubbytes;
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
LS_API_EXEC(crypto_aead_chacha20poly1305, ietf_encrypt)
{
	LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_encrypt) *argv;
	LS_API_READ_ARGV(crypto_aead_chacha20poly1305, ietf_encrypt);

	size_t abytes = crypto_aead_chacha20poly1305_abytes();
	size_t cbytes = argv->mlen + abytes;
	unsigned char c[cbytes];
	unsigned long long clen;

	LS_SAFE_REPLY(crypto_aead_chacha20poly1305_ietf_encrypt(c, &clen, argv->m, argv->mlen, argv->ad, argv->adlen, argv->nsec, argv->npub, argv->k), LS_PROTECT({
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(c), clen,
		ERL_DRV_TUPLE, 2
	}), __FILE__, __LINE__);

	(void) sodium_memzero(c, cbytes);
}

/* crypto_aead_chacha20poly1305_ietf_decrypt/5 */

typedef struct LS_API_F_ARGV(crypto_aead_chacha20poly1305, ietf_decrypt) {
	unsigned char		*nsec;
	const unsigned char	*c;
	unsigned long long	clen;
	const unsigned char	*ad;
	unsigned long long	adlen;
	const unsigned char	*npub;
	const unsigned char	*k;
} LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_decrypt);

static int
LS_API_INIT(crypto_aead_chacha20poly1305, ietf_decrypt)
{
	LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_decrypt) *argv;
	int skip;
	int type;
	int type_length;
	size_t nsecbytes;
	unsigned long long clen;
	unsigned long long adlen;
	size_t ietf_npubbytes;
	size_t keybytes;
	ErlDrvSizeT x;
	void *p;

	nsecbytes = crypto_aead_chacha20poly1305_nsecbytes();

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

	ietf_npubbytes = crypto_aead_chacha20poly1305_ietf_npubbytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != ietf_npubbytes) {
		return -1;
	}

	if (ei_skip_term(buffer, &skip) < 0) {
		return -1;
	}

	keybytes = crypto_aead_chacha20poly1305_keybytes();

	if (ei_get_type(buffer, &skip, &type, &type_length) < 0
			|| type != ERL_BINARY_EXT
			|| type_length != keybytes) {
		return -1;
	}

	x = (ErlDrvSizeT)(nsecbytes + clen + adlen + ietf_npubbytes + keybytes + (sizeof (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_decrypt))));
	p = (void *)(driver_alloc(x));

	if (p == NULL) {
		return -1;
	}

	argv = (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_decrypt) *)(p);
	p += (sizeof (LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_decrypt)));
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
	p += ietf_npubbytes;
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
LS_API_EXEC(crypto_aead_chacha20poly1305, ietf_decrypt)
{
	LS_API_F_ARGV_T(crypto_aead_chacha20poly1305, ietf_decrypt) *argv;
	LS_API_READ_ARGV(crypto_aead_chacha20poly1305, ietf_decrypt);

	size_t abytes = crypto_aead_chacha20poly1305_abytes();
	size_t mbytes = (abytes > argv->clen) ? argv->clen : argv->clen - abytes;
	unsigned char m[mbytes];
	unsigned long long mlen;

	LS_SAFE_REPLY(crypto_aead_chacha20poly1305_ietf_decrypt(m, &mlen, argv->nsec, argv->c, argv->clen, argv->ad, argv->adlen, argv->npub, argv->k), LS_PROTECT({
		LS_RES_TAG(request),
		ERL_DRV_BUF2BINARY, (ErlDrvTermData)(m), mlen,
		ERL_DRV_TUPLE, 2
	}), __FILE__, __LINE__);

	(void) sodium_memzero(m, mbytes);
}
