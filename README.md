# ecewo-cors

## Table of Contents

1. [Installation](#installation)
2. [API](#api)
3. [Default CORS Configuration](#default-cors-configuration)
4. [Custom CORS Configuration](#custom-cors-configuration)
5. [Runtime Configuration](#runtime-configuration)
6. [Statistics](#statistics)

---

## Installation

Add to your `CMakeLists.txt`:

```sh
ecewo_plugin(cors)

target_link_libraries(app PRIVATE
    ecewo::ecewo
    ecewo::cors
)
```

---

## API

```c
typedef struct
{
    const char **origins;         // Array of allowed origins (NULL or "*" to allow all)
    int origins_count;            // Number of origins in the array
    const char *methods;          // Default: "GET, POST, PUT, DELETE, PATCH, OPTIONS"
    const char *allowed_headers;  // Default: "Content-Type, Authorization, X-Requested-With"
    const char *exposed_headers;  // Optional, default: NULL
    bool credentials;             // Default: false
    int max_age;                  // Default: 3600
} Cors;

typedef struct
{
    uint64_t total_requests;
    uint64_t preflight_requests;
    uint64_t allowed_requests;
    uint64_t rejected_requests;
    int configured_origins;
    bool allow_all_origins;
} CorsStats;

// Initialization and cleanup
int cors_init(const Cors *config);  // Returns 0 on success, -1 on failure
void cors_cleanup(void);

// Runtime origin management
int cors_add_origin(const char *origin);
int cors_remove_origin(const char *origin);
bool cors_is_origin_allowed(const char *origin);

// Statistics
void cors_get_stats(CorsStats *stats);
void cors_reset_stats(void);
```

---

## Default CORS Configuration

```c
#include "ecewo.h"
#include "ecewo-cors.h"
#include <stdio.h>

int main(void) {
    if (server_init() != SERVER_OK) {
        fprintf(stderr, "Failed to initialize server\n");
        return 1;
    }

    // Register CORS with default settings (allow all origins)
    cors_init(NULL);

    get("/", example_handler);

    server_atexit(cors_cleanup);

    if (server_listen(3000) != SERVER_OK){
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    server_run();
    return 0;
}
```

---

## Custom CORS Configuration

```c
#include "ecewo.h"
#include "ecewo-cors.h"
#include <stdio.h>

// Configure CORS with multiple origins and custom settings
static const char *origins[] = {
    "http://localhost:3000",
    "http://example.com"
};

static const Cors cors_config = {
    .origins = origins,
    .origins_count = 2,
    .methods = "GET, POST, OPTIONS",
    .allowed_headers = "Content-Type, Authorization",
    .exposed_headers = "X-Custom-Header",
    .credentials = true,
    .max_age = 86400,
};

int main(void) {
    if (server_init() != SERVER_OK) {
        fprintf(stderr, "Failed to initialize server\n");
        return 1;
    }

    // Register CORS with custom settings
    if (cors_init(&cors_config) != 0) {
        fprintf(stderr, "Failed to initialize CORS\n");
        return 1;
    }

    get("/", example_handler);

    server_atexit(cors_cleanup);

    if (server_listen(3000) != SERVER_OK) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    server_run();
    return 0;
}
```

> [!IMPORTANT]
>
> All strings in `Cors` config (origins, methods, headers) must have **static lifetime** and remain valid for the lifetime of the server.

---

## Runtime Configuration

```c
// Add a new origin at runtime
cors_add_origin("http://newsite.com");

// Remove an origin at runtime
cors_remove_origin("http://example.com");

// Check if an origin is allowed
if (cors_is_origin_allowed("http://localhost:3000")) {
    // proceed
}
```

---

## Statistics

```c
CorsStats stats;
cors_get_stats(&stats);
printf("Total requests: %llu\n", stats.total_requests);
printf("Preflight requests: %llu\n", stats.preflight_requests);
printf("Allowed requests: %llu\n", stats.allowed_requests);
printf("Rejected requests: %llu\n", stats.rejected_requests);
printf("Configured origins: %d\n", stats.configured_origins);
printf("Allow all origins: %s\n", stats.allow_all_origins ? "true" : "false");

// Reset statistics
cors_reset_stats();
```
