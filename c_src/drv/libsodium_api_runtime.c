// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_runtime.h"

static void LS_API_EXEC(runtime, has_neon);
static void LS_API_EXEC(runtime, has_sse2);
static void LS_API_EXEC(runtime, has_sse3);
static void LS_API_EXEC(runtime, has_ssse3);
static void LS_API_EXEC(runtime, has_sse41);
static void LS_API_EXEC(runtime, has_avx);
static void LS_API_EXEC(runtime, has_avx2);
static void LS_API_EXEC(runtime, has_avx512f);
static void LS_API_EXEC(runtime, has_pclmul);
static void LS_API_EXEC(runtime, has_aesni);
static void LS_API_EXEC(runtime, has_rdrand);

libsodium_function_t libsodium_functions_runtime[] = {
    LS_API_R_ARG0(runtime, has_neon),  LS_API_R_ARG0(runtime, has_sse2),    LS_API_R_ARG0(runtime, has_sse3),
    LS_API_R_ARG0(runtime, has_ssse3), LS_API_R_ARG0(runtime, has_sse41),   LS_API_R_ARG0(runtime, has_avx),
    LS_API_R_ARG0(runtime, has_avx2),  LS_API_R_ARG0(runtime, has_avx512f), LS_API_R_ARG0(runtime, has_pclmul),
    LS_API_R_ARG0(runtime, has_aesni), LS_API_R_ARG0(runtime, has_rdrand),  {NULL}};

#define LS_API_RUNTIME_HAS(FEATURE, FILE, LINE)                                                                                    \
    static void LS_API_EXEC(runtime, has_##FEATURE)                                                                                \
    {                                                                                                                              \
        int r;                                                                                                                     \
        r = sodium_runtime_has_##FEATURE();                                                                                        \
        ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(r), ERL_DRV_TUPLE, 2};                             \
        LS_RESPOND(request, spec, FILE, LINE);                                                                                     \
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

/* runtime_has_avx2/0 */

LS_API_RUNTIME_HAS(avx2, __FILE__, __LINE__);

/* runtime_has_avx512f/0 */

LS_API_RUNTIME_HAS(avx512f, __FILE__, __LINE__);

/* runtime_has_pclmul/0 */

LS_API_RUNTIME_HAS(pclmul, __FILE__, __LINE__);

/* runtime_has_aesni/0 */

LS_API_RUNTIME_HAS(aesni, __FILE__, __LINE__);

/* runtime_has_rdrand/0 */

LS_API_RUNTIME_HAS(rdrand, __FILE__, __LINE__);
