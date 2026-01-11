#ifndef ECEWO_CORS_H
#define ECEWO_CORS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

typedef struct {
  const char **allowed_origins;
  int allowed_origins_count;
  const char *allowed_methods;
  const char *allowed_headers;
  const char *exposed_headers;
  bool allow_credentials;
  int max_age;
} Cors;

/**
 * Initialize CORS middleware
 *
 * @param options - CORS configuration (NULL = use all defaults)
 *
 * Must be called before routes are registered.
 * Automatically registers middleware via use().
 *
 * Thread-safe: Safe to call once during startup
 *
 * Examples:
 *
 *   // Allow all origins (development only!)
 *   cors_init(NULL);
 *
 *   // Production: specific origins
 *   const char *origins[] = { "https://myapp.com" };
 *   Cors opts = {
 *       .allowed_origins = origins,
 *       .allowed_origins_count = 1,
 *       .allow_credentials = true
 *   };
 *   cors_init(&opts);
 *
 *   // Multiple origins with custom headers
 *   const char *origins[] = {
 *       "https://app1.com",
 *       "https://app2.com"
 *   };
 *   Cors opts = {
 *       .allowed_origins = origins,
 *       .allowed_origins_count = 2,
 *       .allowed_headers = "Content-Type, Authorization, X-API-Key",
 *       .exposed_headers = "X-Total-Count, X-Page-Count",
 *       .allow_credentials = true,
 *       .max_age = 7200
 *   };
 *   cors_init(&opts);
 *
 * Returns: 1 on success, 0 on failure
 */
int cors_init(const Cors *options);

/**
 * Cleanup CORS module
 * Frees all allocated memory
 * Call at application shutdown
 */
void cors_cleanup(void);

// ============================================================================
// Runtime Configuration (Optional)
// ============================================================================

/**
 * Add allowed origin dynamically
 * Thread-safe
 *
 * Example:
 *   cors_add_origin("https://newapp.com");
 *
 * Returns: 1 on success, 0 on failure
 */
int cors_add_origin(const char *origin);

// Returns: 1 if removed, 0 if not found
int cors_remove_origin(const char *origin);

bool cors_is_origin_allowed(const char *origin);

typedef struct {
  uint64_t total_requests; // Total CORS requests processed
  uint64_t preflight_requests; // OPTIONS requests
  uint64_t allowed_requests; // Requests from allowed origins
  uint64_t rejected_requests; // Requests from forbidden origins
  int configured_origins; // Number of configured origins
  bool allow_all_origins; // Whether "*" is configured
} CorsStats;

void cors_get_stats(CorsStats *stats);
void cors_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif
