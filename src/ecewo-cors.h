// Copyright 2025-2026 Savas Sahin <savashn@proton.me>

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#ifndef ECEWO_CORS_H
#define ECEWO_CORS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "ecewo.h"
#include "ecewo-cors-export.h"

/**
 * Opaque CORS configuration builder.
 *
 * Created with ecewo_cors_config_new(); populate via the
 * ecewo_cors_config_set_*() and ecewo_cors_config_add_origin() setters; then
 * either install it on an app via ecewo_cors_install(), or discard it via
 * ecewo_cors_config_free(). Once installed, the configuration is consumed and
 * the caller must NOT free it - its lifetime is taken over by the app.
 */
typedef struct ecewo_cors_config_s ecewo_cors_config_t;

// ---------------------------------------------------------------------------
// CONFIGURATION BUILDER
// ---------------------------------------------------------------------------

/** Allocate a new CORS configuration with default values.
 *  Returns NULL on allocation failure. The caller owns the handle until it is
 *  passed to ecewo_cors_install(); after install the handle is consumed. */
ECEWO_CORS_EXPORT ecewo_cors_config_t *ecewo_cors_config_new(void);

/** Free a CORS configuration that has not yet been installed.
 *  After ecewo_cors_install() the configuration is owned by the app and must
 *  not be freed by the caller. */
ECEWO_CORS_EXPORT void ecewo_cors_config_free(ecewo_cors_config_t *config);

/** Append an allowed origin (e.g. "https://example.com") or "*" for any origin.
 *  Returns 0 on success, -1 on error (NULL args, allocation failure). */
ECEWO_CORS_EXPORT int ecewo_cors_config_add_origin(ecewo_cors_config_t *config, const char *origin);

/** Set the value for the `Access-Control-Allow-Methods` preflight header.
 *  When unset, the default is "GET, POST, PUT, DELETE, PATCH, OPTIONS".
 *  The string is copied; the caller may free it after this call. */
ECEWO_CORS_EXPORT int ecewo_cors_config_set_methods(ecewo_cors_config_t *config, const char *methods);

/** Set the value for the `Access-Control-Allow-Headers` preflight header.
 *  When unset, the default is "Content-Type, Authorization, X-Requested-With".
 *  The string is copied; the caller may free it after this call. */
ECEWO_CORS_EXPORT int ecewo_cors_config_set_allowed_headers(ecewo_cors_config_t *config, const char *headers);

/** Set the value for the `Access-Control-Expose-Headers` response header.
 *  Pass NULL or empty string to disable the header. The string is copied. */
ECEWO_CORS_EXPORT int ecewo_cors_config_set_exposed_headers(ecewo_cors_config_t *config, const char *headers);

/** Enable or disable the `Access-Control-Allow-Credentials: true` header.
 *  Cannot be combined with origin "*"; ecewo_cors_install() will fail in that case. */
ECEWO_CORS_EXPORT void ecewo_cors_config_set_credentials(ecewo_cors_config_t *config, bool credentials);

/** Set the value for the `Access-Control-Max-Age` preflight header in seconds.
 *  Default is 3600. Values <= 0 reset to the default. */
ECEWO_CORS_EXPORT void ecewo_cors_config_set_max_age(ecewo_cors_config_t *config, int max_age);

// ---------------------------------------------------------------------------
// INSTALLATION
// ---------------------------------------------------------------------------

/** Install the CORS configuration on the given app and register the CORS
 *  middleware globally. On success the configuration is consumed - its memory
 *  is moved into the app arena and the handle must not be freed or accessed
 *  again. On failure the configuration is also freed; do not use it again.
 *
 *  Each app may have at most one CORS installation. Calling this twice on the
 *  same app returns -1.
 *
 *  When `config` is NULL, a default configuration is used: origin "*", standard
 *  methods/headers, no credentials, max-age 3600. Returns 0 on success, -1 on
 *  error. */
ECEWO_CORS_EXPORT int ecewo_cors_install(ecewo_app_t *app, ecewo_cors_config_t *config);

// ---------------------------------------------------------------------------
// RUNTIME ORIGIN MANAGEMENT
// ---------------------------------------------------------------------------

/** Add an origin at runtime to an installed CORS configuration.
 *  Must be called from the event loop thread. Returns 0 on success (or already
 *  present), -1 on error. */
ECEWO_CORS_EXPORT int ecewo_cors_add_origin(ecewo_app_t *app, const char *origin);

/** Remove an origin previously added either at config or runtime.
 *  Must be called from the event loop thread. Returns 0 on success, -1 if the
 *  origin was not found or on error. */
ECEWO_CORS_EXPORT int ecewo_cors_remove_origin(ecewo_app_t *app, const char *origin);

/** Return true if `origin` is currently allowed by the installed configuration.
 *  Returns false if CORS is not installed on the app or on NULL inputs. */
ECEWO_CORS_EXPORT bool ecewo_cors_is_origin_allowed(const ecewo_app_t *app, const char *origin);

// ---------------------------------------------------------------------------
// STATISTICS
// ---------------------------------------------------------------------------

/** Total number of requests seen by the CORS middleware on this app. */
ECEWO_CORS_EXPORT uint64_t ecewo_cors_stat_total(const ecewo_app_t *app);

/** Number of OPTIONS preflight requests handled. */
ECEWO_CORS_EXPORT uint64_t ecewo_cors_stat_preflight(const ecewo_app_t *app);

/** Number of requests for which CORS allowed the origin. */
ECEWO_CORS_EXPORT uint64_t ecewo_cors_stat_allowed(const ecewo_app_t *app);

/** Number of requests rejected because the origin was not on the allow list. */
ECEWO_CORS_EXPORT uint64_t ecewo_cors_stat_rejected(const ecewo_app_t *app);

/** Number of origins currently configured (counting "*" as one). */
ECEWO_CORS_EXPORT int ecewo_cors_stat_origin_count(const ecewo_app_t *app);

/** Whether the wildcard "*" origin is currently configured. */
ECEWO_CORS_EXPORT bool ecewo_cors_stat_allow_all(const ecewo_app_t *app);

/** Reset all CORS request counters to zero. Origin configuration is unchanged. */
ECEWO_CORS_EXPORT void ecewo_cors_reset_stats(ecewo_app_t *app);

#ifdef __cplusplus
}
#endif

#endif
