# ecewo-cors

CORS middleware for [ecewo](https://github.com/ecewo/ecewo).

## Table of Contents

1. [Installation](#installation)
2. [API](#api)
3. [Default CORS Configuration](#default-cors-configuration)
4. [Custom CORS Configuration](#custom-cors-configuration)
5. [Runtime Origin Management](#runtime-origin-management)
6. [Statistics](#statistics)

---

## Installation

Add to your `CMakeLists.txt`:

```cmake
ecewo_add(cors@v0.2.0)

target_link_libraries(app PRIVATE
    ecewo::ecewo
    ecewo::cors
)
```

---

## API

The configuration is built with a heap-backed builder, then handed to
`ecewo_cors_install()` which copies it into the app arena and registers the
middleware. Each app may have at most one CORS installation.

```c
// Opaque builder. Allocate, populate, then install (or free).
typedef struct ecewo_cors_config_s ecewo_cors_config_t;

// --- Builder ---
ecewo_cors_config_t *ecewo_cors_config_new(void);
void ecewo_cors_config_free(ecewo_cors_config_t *config);

int  ecewo_cors_config_add_origin(ecewo_cors_config_t *config, const char *origin);
int  ecewo_cors_config_set_methods(ecewo_cors_config_t *config, const char *methods);
int  ecewo_cors_config_set_allowed_headers(ecewo_cors_config_t *config, const char *headers);
int  ecewo_cors_config_set_exposed_headers(ecewo_cors_config_t *config, const char *headers);
void ecewo_cors_config_set_credentials(ecewo_cors_config_t *config, bool credentials);
void ecewo_cors_config_set_max_age(ecewo_cors_config_t *config, int max_age);

// --- Installation ---
// Consumes `config` (success or failure). Pass NULL for defaults.
int  ecewo_cors_install(ecewo_app_t *app, ecewo_cors_config_t *config);

// --- Runtime origin management ---
int  ecewo_cors_add_origin(ecewo_app_t *app, const char *origin);
int  ecewo_cors_remove_origin(ecewo_app_t *app, const char *origin);
bool ecewo_cors_is_origin_allowed(const ecewo_app_t *app, const char *origin);

// --- Statistics ---
uint64_t ecewo_cors_stat_total(const ecewo_app_t *app);
uint64_t ecewo_cors_stat_preflight(const ecewo_app_t *app);
uint64_t ecewo_cors_stat_allowed(const ecewo_app_t *app);
uint64_t ecewo_cors_stat_rejected(const ecewo_app_t *app);
int      ecewo_cors_stat_origin_count(const ecewo_app_t *app);
bool     ecewo_cors_stat_allow_all(const ecewo_app_t *app);
void     ecewo_cors_reset_stats(ecewo_app_t *app);
```

Defaults applied when not overridden:

| Field             | Default                                       |
| ----------------- | --------------------------------------------- |
| origin            | `*` (wildcard)                                |
| methods           | `GET, POST, PUT, DELETE, PATCH, OPTIONS`      |
| allowed headers   | `Content-Type, Authorization, X-Requested-With` |
| exposed headers   | none                                          |
| credentials       | `false`                                       |
| max-age           | `3600` seconds                                |

> [!IMPORTANT]
> `credentials = true` cannot be combined with origin `*`. The CORS spec
> forbids it, and `ecewo_cors_install()` will fail in that case.

---

## Default CORS Configuration

Pass `NULL` to install the defaults (wildcard origin, standard methods/headers,
no credentials).

```c
#include "ecewo.h"
#include "ecewo-cors.h"

static void hello(ecewo_request_t *req, ecewo_response_t *res) {
    (void)req;
    ecewo_send_text(res, 200, "hello");
}

int main(void) {
    ecewo_app_t *app = ecewo_create();

    if (ecewo_cors_install(app, NULL) != 0)
        return 1;

    ECEWO_GET(app, "/", hello);

    ecewo_listen(app, 3000);
    return 0;
}
```

---

## Custom CORS Configuration

Build the config with the `ecewo_cors_config_*` setters, then install. After a
successful install the config handle is consumed — do not free or reuse it.

```c
#include "ecewo.h"
#include "ecewo-cors.h"

int main(void) {
    ecewo_app_t *app = ecewo_create();

    ecewo_cors_config_t *cfg = ecewo_cors_config_new();
    if (!cfg) return 1;

    ecewo_cors_config_add_origin(cfg, "http://localhost:3000");
    ecewo_cors_config_add_origin(cfg, "http://example.com");
    ecewo_cors_config_set_methods(cfg, "GET, POST");
    ecewo_cors_config_set_allowed_headers(cfg, "Content-Type, Authorization");
    ecewo_cors_config_set_exposed_headers(cfg, "X-Custom-Header");
    ecewo_cors_config_set_credentials(cfg, true);
    ecewo_cors_config_set_max_age(cfg, 86400);

    if (ecewo_cors_install(app, cfg) != 0)
        return 1;
    // cfg is now owned by the app; do not free or reuse.

    ECEWO_GET(app, "/", hello);

    ecewo_listen(app, 3000);
    return 0;
}
```

Strings passed to the setters are copied internally, so the source buffers do
not need to outlive the call.

---

## Runtime Origin Management

Origins can be added or removed after install. These calls must run on the
event-loop thread (e.g. from a request handler or a timer callback).

```c
ecewo_cors_add_origin(app, "http://newsite.com");
ecewo_cors_remove_origin(app, "http://example.com");

if (ecewo_cors_is_origin_allowed(app, "http://localhost:3000")) {
    // proceed
}
```

---

## Statistics

Each counter is a separate accessor. Counters are per-app.

```c
printf("Total:      %" PRIu64 "\n", ecewo_cors_stat_total(app));
printf("Preflight:  %" PRIu64 "\n", ecewo_cors_stat_preflight(app));
printf("Allowed:    %" PRIu64 "\n", ecewo_cors_stat_allowed(app));
printf("Rejected:   %" PRIu64 "\n", ecewo_cors_stat_rejected(app));
printf("Origins:    %d\n",          ecewo_cors_stat_origin_count(app));
printf("Allow all:  %s\n",          ecewo_cors_stat_allow_all(app) ? "true" : "false");

ecewo_cors_reset_stats(app);
```
