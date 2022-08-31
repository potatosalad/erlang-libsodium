// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api.h"
#include "libsodium_api_crypto_aead_aes256gcm.h"
#include "libsodium_api_crypto_aead_chacha20poly1305.h"
#include "libsodium_api_crypto_aead_xchacha20poly1305.h"
#include "libsodium_api_crypto_auth.h"
#include "libsodium_api_crypto_auth_hmacsha256.h"
#include "libsodium_api_crypto_auth_hmacsha512.h"
#include "libsodium_api_crypto_auth_hmacsha512256.h"
#include "libsodium_api_crypto_box.h"
#include "libsodium_api_crypto_box_curve25519xchacha20poly1305.h"
#include "libsodium_api_crypto_box_curve25519xsalsa20poly1305.h"
#include "libsodium_api_crypto_core_ed25519.h"
#include "libsodium_api_crypto_core_hchacha20.h"
#include "libsodium_api_crypto_core_hsalsa20.h"
#include "libsodium_api_crypto_core_ristretto255.h"
#include "libsodium_api_crypto_core_salsa20.h"
#include "libsodium_api_crypto_core_salsa2012.h"
#include "libsodium_api_crypto_generichash.h"
#include "libsodium_api_crypto_generichash_blake2b.h"
#include "libsodium_api_crypto_hash.h"
#include "libsodium_api_crypto_hash_sha256.h"
#include "libsodium_api_crypto_hash_sha512.h"
#include "libsodium_api_crypto_kdf.h"
#include "libsodium_api_crypto_kdf_blake2b.h"
#include "libsodium_api_crypto_kx.h"
#include "libsodium_api_crypto_onetimeauth.h"
#include "libsodium_api_crypto_onetimeauth_poly1305.h"
#include "libsodium_api_crypto_pwhash.h"
#include "libsodium_api_crypto_pwhash_argon2i.h"
#include "libsodium_api_crypto_pwhash_argon2id.h"
#include "libsodium_api_crypto_pwhash_scryptsalsa208sha256.h"
#include "libsodium_api_crypto_scalarmult.h"
#include "libsodium_api_crypto_scalarmult_curve25519.h"
#include "libsodium_api_crypto_scalarmult_ed25519.h"
#include "libsodium_api_crypto_scalarmult_ristretto255.h"
#include "libsodium_api_crypto_secretbox.h"
#include "libsodium_api_crypto_secretbox_xchacha20poly1305.h"
#include "libsodium_api_crypto_secretbox_xsalsa20poly1305.h"
#include "libsodium_api_crypto_secretstream_xchacha20poly1305.h"
#include "libsodium_api_crypto_shorthash.h"
#include "libsodium_api_crypto_shorthash_siphash24.h"
#include "libsodium_api_crypto_shorthash_siphashx24.h"
#include "libsodium_api_crypto_sign.h"
#include "libsodium_api_crypto_sign_ed25519.h"
#include "libsodium_api_crypto_sign_ed25519ph.h"
#include "libsodium_api_crypto_stream.h"
#include "libsodium_api_crypto_stream_chacha20.h"
#include "libsodium_api_crypto_stream_salsa20.h"
#include "libsodium_api_crypto_stream_salsa2012.h"
#include "libsodium_api_crypto_stream_xchacha20.h"
#include "libsodium_api_crypto_stream_xsalsa20.h"
#include "libsodium_api_crypto_verify_16.h"
#include "libsodium_api_crypto_verify_32.h"
#include "libsodium_api_crypto_verify_64.h"
#include "libsodium_api_randombytes.h"
#include "libsodium_api_runtime.h"
#include "libsodium_api_utils.h"
#include "libsodium_api_version.h"

#define LS_NS(NAMESPACE)                                                                                                           \
    {                                                                                                                              \
#NAMESPACE, libsodium_functions_##NAMESPACE                                                                                \
    }

static libsodium_namespace_t libsodium_namespaces[] = {LS_NS(crypto_aead_aes256gcm),
                                                       LS_NS(crypto_aead_chacha20poly1305),
                                                       LS_NS(crypto_aead_xchacha20poly1305),
                                                       LS_NS(crypto_auth),
                                                       LS_NS(crypto_auth_hmacsha256),
                                                       LS_NS(crypto_auth_hmacsha512),
                                                       LS_NS(crypto_auth_hmacsha512256),
                                                       LS_NS(crypto_box),
                                                       LS_NS(crypto_box_curve25519xchacha20poly1305),
                                                       LS_NS(crypto_box_curve25519xsalsa20poly1305),
                                                       LS_NS(crypto_core_ed25519),
                                                       LS_NS(crypto_core_hchacha20),
                                                       LS_NS(crypto_core_hsalsa20),
                                                       LS_NS(crypto_core_ristretto255),
                                                       LS_NS(crypto_core_salsa20),
                                                       LS_NS(crypto_core_salsa2012),
                                                       LS_NS(crypto_generichash),
                                                       LS_NS(crypto_generichash_blake2b),
                                                       LS_NS(crypto_hash),
                                                       LS_NS(crypto_hash_sha256),
                                                       LS_NS(crypto_hash_sha512),
                                                       LS_NS(crypto_kdf),
                                                       LS_NS(crypto_kdf_blake2b),
                                                       LS_NS(crypto_kx),
                                                       LS_NS(crypto_onetimeauth),
                                                       LS_NS(crypto_onetimeauth_poly1305),
                                                       LS_NS(crypto_pwhash),
                                                       LS_NS(crypto_pwhash_argon2i),
                                                       LS_NS(crypto_pwhash_argon2id),
                                                       LS_NS(crypto_pwhash_scryptsalsa208sha256),
                                                       LS_NS(crypto_scalarmult),
                                                       LS_NS(crypto_scalarmult_curve25519),
                                                       LS_NS(crypto_scalarmult_ed25519),
                                                       LS_NS(crypto_scalarmult_ristretto255),
                                                       LS_NS(crypto_secretbox),
                                                       LS_NS(crypto_secretbox_xchacha20poly1305),
                                                       LS_NS(crypto_secretbox_xsalsa20poly1305),
                                                       LS_NS(crypto_secretstream_xchacha20poly1305),
                                                       LS_NS(crypto_shorthash),
                                                       LS_NS(crypto_shorthash_siphash24),
                                                       LS_NS(crypto_shorthash_siphashx24),
                                                       LS_NS(crypto_sign),
                                                       LS_NS(crypto_sign_ed25519),
                                                       LS_NS(crypto_sign_ed25519ph),
                                                       LS_NS(crypto_stream),
                                                       LS_NS(crypto_stream_chacha20),
                                                       LS_NS(crypto_stream_salsa20),
                                                       LS_NS(crypto_stream_salsa2012),
                                                       LS_NS(crypto_stream_xchacha20),
                                                       LS_NS(crypto_stream_xsalsa20),
                                                       LS_NS(crypto_verify_16),
                                                       LS_NS(crypto_verify_32),
                                                       LS_NS(crypto_verify_64),
                                                       LS_NS(randombytes),
                                                       LS_NS(runtime),
                                                       LS_NS(utils),
                                                       LS_NS(version),
                                                       {NULL}};

void
init_libsodium_api(void)
{
    libsodium_namespace_t *n;
    libsodium_function_t *f;

    n = NULL;
    f = NULL;

    for (n = libsodium_namespaces; n->namespace; n++) {
        n->am_namespace = driver_mk_atom((char *)(n->namespace));
        for (f = n->functions; f->function; f++) {
            f->am_function = driver_mk_atom((char *)(f->function));
        }
    }

    (void)init_libsodium_api_randombytes_implementation();
    (void)init_libsodium_api_utils_base64_variants();
}

libsodium_function_t *
get_libsodium_api(const char *namespace, const char *function)
{
    libsodium_namespace_t *n;
    libsodium_function_t *f;
    ErlDrvTermData am_namespace;
    ErlDrvTermData am_function;

    n = NULL;
    f = NULL;

    // (void) erl_drv_mutex_lock(libsodium_mutex);
    am_namespace = driver_mk_atom((char *)namespace);
    am_function = driver_mk_atom((char *)function);
    // (void) erl_drv_mutex_unlock(libsodium_mutex);

    for (n = libsodium_namespaces; n->namespace; n++) {
        if (n->am_namespace == am_namespace) {
            for (f = n->functions; f->function; f++) {
                if (f->am_function == am_function) {
                    return f;
                }
            }
            return NULL;
        }
    }

    return NULL;
}
