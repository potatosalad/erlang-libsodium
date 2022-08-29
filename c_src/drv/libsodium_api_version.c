// -*- mode: c; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
// vim: ts=4 sw=4 ft=c et

#include "libsodium_api_version.h"

SODIUM_EXPORT
const char *sodium_version_string(void);

SODIUM_EXPORT
int sodium_library_version_major(void);

SODIUM_EXPORT
int sodium_library_version_minor(void);

static void LS_API_EXEC(version, version_string);
static void LS_API_EXEC(version, library_version_major);
static void LS_API_EXEC(version, library_version_minor);

libsodium_function_t libsodium_functions_version[] = {LS_API_R_ARG0(version, version_string),
                                                      LS_API_R_ARG0(version, library_version_major),
                                                      LS_API_R_ARG0(version, library_version_minor),
                                                      {NULL}};

/* version_version_string/0 */

static void
LS_API_EXEC(version, version_string)
{
    const char *string;

    string = sodium_version_string();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_BUF2BINARY, (ErlDrvTermData)(string), strlen(string), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* version_library_version_major/0 */

static void
LS_API_EXEC(version, library_version_major)
{
    int major;

    major = sodium_library_version_major();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(major), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}

/* version_library_version_minor/0 */

static void
LS_API_EXEC(version, library_version_minor)
{
    int minor;

    minor = sodium_library_version_minor();

    ErlDrvTermData spec[] = {LS_RES_TAG(request), ERL_DRV_INT, (ErlDrvSInt)(minor), ERL_DRV_TUPLE, 2};

    LS_RESPOND(request, spec, __FILE__, __LINE__);
}
