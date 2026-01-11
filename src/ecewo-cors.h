#ifndef ECEWO_CORS_H
#define ECEWO_CORS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

typedef struct {
  const char **origins;
  int origins_count;
  const char *methods;
  const char *allowed_headers;
  const char *exposed_headers;
  bool credentials;
  int max_age;
} Cors;

// Returns: 0 on success, -1 on failure
int cors_init(const Cors *options);

void cors_cleanup(void);

// Returns: 0 on success, -1 on failure
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
