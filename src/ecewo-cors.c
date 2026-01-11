#include "ecewo-cors.h"
#include "ecewo.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <uv.h>

static const char *DEFAULT_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS";
static const char *DEFAULT_HEADERS = "Content-Type, Authorization, X-Requested-With";
static const int DEFAULT_MAX_AGE = 3600;

typedef struct origin_node_s {
  char *origin;
  struct origin_node_s *next;
} origin_node_t;

typedef struct {
  origin_node_t *origins;
  int origin_count;
  bool allow_all_origins; // True if "*" is in origins

  char *allowed_methods;
  char *allowed_headers;
  char *exposed_headers;
  bool allow_credentials;
  int max_age;

  // Statistics
  uint64_t total_requests;
  uint64_t preflight_requests;
  uint64_t allowed_requests;
  uint64_t rejected_requests;

  bool initialized;
} cors_state_t;

static cors_state_t cors_state = { 0 };

static bool is_origin_allowed_internal(const char *request_origin) {
  if (!request_origin)
    return false;

  if (cors_state.allow_all_origins)
    return true;

  origin_node_t *node = cors_state.origins;
  while (node) {
    if (strcmp(node->origin, request_origin) == 0)
      return true;
    node = node->next;
  }

  return false;
}

static void cors_middleware(Req *req, Res *res, Next next) {
  if (!cors_state.initialized) {
    next(req, res);
    return;
  }

  cors_state.total_requests++;

  const char *request_origin = get_header(req, "Origin");

  if (req->method && strcmp(req->method, "OPTIONS") == 0) {
    cors_state.preflight_requests++;

    if (request_origin && !is_origin_allowed_internal(request_origin)) {
      cors_state.rejected_requests++;
      send_text(res, 403, "CORS: Origin not allowed");
      return;
    }

    cors_state.allowed_requests++;

    if (cors_state.allow_all_origins) {
      set_header(res, "Access-Control-Allow-Origin", "*");
    } else if (request_origin) {
      set_header(res, "Access-Control-Allow-Origin", request_origin);
      set_header(res, "Vary", "Origin");
    }

    set_header(res, "Access-Control-Allow-Methods", cors_state.allowed_methods);
    set_header(res, "Access-Control-Allow-Headers", cors_state.allowed_headers);

    if (cors_state.allow_credentials) {
      set_header(res, "Access-Control-Allow-Credentials", "true");
    }

    char max_age_str[32];
    snprintf(max_age_str, sizeof(max_age_str), "%d", cors_state.max_age);
    set_header(res, "Access-Control-Max-Age", max_age_str);

    reply(res, 204, NULL, 0);
    return;
  }

  bool should_add_headers = false;

  if (cors_state.allow_all_origins) {
    set_header(res, "Access-Control-Allow-Origin", "*");
    should_add_headers = true;
    cors_state.allowed_requests++;
  } else if (request_origin && is_origin_allowed_internal(request_origin)) {
    set_header(res, "Access-Control-Allow-Origin", request_origin);
    set_header(res, "Vary", "Origin");
    should_add_headers = true;
    cors_state.allowed_requests++;
  } else if (request_origin) {
    cors_state.rejected_requests++;
  }

  if (should_add_headers) {
    if (cors_state.allow_credentials) {
      set_header(res, "Access-Control-Allow-Credentials", "true");
    }

    if (cors_state.exposed_headers) {
      set_header(res, "Access-Control-Expose-Headers", cors_state.exposed_headers);
    }
  }

  next(req, res);
}

static void free_origins_list(void) {
  origin_node_t *node = cors_state.origins;
  while (node) {
    origin_node_t *next = node->next;
    free(node->origin);
    free(node);
    node = next;
  }
  cors_state.origins = NULL;
  cors_state.origin_count = 0;
}

static int add_origin_internal(const char *origin) {
  if (!origin)
    return 0;

  origin_node_t *node = cors_state.origins;
  while (node) {
    if (strcmp(node->origin, origin) == 0)
      return 1;
    node = node->next;
  }

  origin_node_t *new_node = malloc(sizeof(origin_node_t));
  if (!new_node)
    return 0;

  new_node->origin = strdup(origin);
  if (!new_node->origin) {
    free(new_node);
    return 0;
  }

  new_node->next = cors_state.origins;
  cors_state.origins = new_node;
  cors_state.origin_count++;

  if (strcmp(origin, "*") == 0) {
    cors_state.allow_all_origins = true;
  }

  return 1;
}

static Cors cors_default_options(void) {
  Cors opts = {
    .allowed_origins = NULL,
    .allowed_origins_count = 0,
    .allowed_methods = NULL,
    .allowed_headers = NULL,
    .exposed_headers = NULL,
    .allow_credentials = false,
    .max_age = DEFAULT_MAX_AGE
  };
  return opts;
}

int cors_init(const Cors *options) {
  if (cors_state.initialized) {
    fprintf(stderr, "[ecewo-cors] Already initialized\n");
    return 0;
  }

  Cors opts = options ? *options : cors_default_options();

  if (opts.allowed_origins && opts.allowed_origins_count > 0) {
    for (int i = 0; i < opts.allowed_origins_count; i++) {
      if (!add_origin_internal(opts.allowed_origins[i])) {
        fprintf(stderr, "[ecewo-cors] Failed to add origin: %s\n",
                opts.allowed_origins[i]);
        cors_cleanup();
        return 0;
      }
    }
  } else {
    if (!add_origin_internal("*")) {
      fprintf(stderr, "[ecewo-cors] Failed to set default origin\n");
      cors_cleanup();
      return 0;
    }
  }

  if (opts.allow_credentials && cors_state.allow_all_origins) {
    fprintf(stderr, "[ecewo-cors] ERROR: Cannot use credentials=true with origin=*\n");
    fprintf(stderr, "[ecewo-cors] This violates CORS specification!\n");
    fprintf(stderr, "[ecewo-cors] Please specify explicit origins when using credentials.\n");
    cors_cleanup();
    return 0;
  }

  cors_state.allowed_methods = opts.allowed_methods
      ? strdup(opts.allowed_methods)
      : strdup(DEFAULT_METHODS);

  cors_state.allowed_headers = opts.allowed_headers
      ? strdup(opts.allowed_headers)
      : strdup(DEFAULT_HEADERS);

  cors_state.exposed_headers = opts.exposed_headers
      ? strdup(opts.exposed_headers)
      : NULL;

  cors_state.allow_credentials = opts.allow_credentials;
  cors_state.max_age = opts.max_age > 0 ? opts.max_age : DEFAULT_MAX_AGE;

  if (!cors_state.allowed_methods || !cors_state.allowed_headers) {
    fprintf(stderr, "[ecewo-cors] Memory allocation failed\n");
    cors_cleanup();
    return 0;
  }

  cors_state.initialized = true;

  use(cors_middleware);

  return 1;
}

void cors_cleanup(void) {
  free_origins_list();
  free(cors_state.allowed_methods);
  free(cors_state.allowed_headers);
  free(cors_state.exposed_headers);

  cors_state.allowed_methods = NULL;
  cors_state.allowed_headers = NULL;
  cors_state.exposed_headers = NULL;

  cors_state.allow_all_origins = false;
  cors_state.allow_credentials = false;
  cors_state.max_age = DEFAULT_MAX_AGE;

  cors_state.total_requests = 0;
  cors_state.preflight_requests = 0;
  cors_state.allowed_requests = 0;
  cors_state.rejected_requests = 0;

  cors_state.origin_count = 0;

  cors_state.initialized = false;
}

int cors_add_origin(const char *origin) {
  if (!origin || !cors_state.initialized)
    return 0;

  int result = add_origin_internal(origin);

  return result;
}

int cors_remove_origin(const char *origin) {
  if (!origin || !cors_state.initialized)
    return 0;

  origin_node_t *prev = NULL;
  origin_node_t *node = cors_state.origins;

  while (node) {
    if (strcmp(node->origin, origin) == 0) {
      if (prev) {
        prev->next = node->next;
      } else {
        cors_state.origins = node->next;
      }

      if (strcmp(node->origin, "*") == 0) {
        cors_state.allow_all_origins = false;
      }

      free(node->origin);
      free(node);
      cors_state.origin_count--;

      return 1;
    }
    prev = node;
    node = node->next;
  }

  return 0;
}

bool cors_is_origin_allowed(const char *origin) {
  if (!origin || !cors_state.initialized)
    return false;

  bool allowed = is_origin_allowed_internal(origin);

  return allowed;
}

void cors_get_stats(CorsStats *stats) {
  if (!stats || !cors_state.initialized)
    return;

  stats->total_requests = cors_state.total_requests;
  stats->preflight_requests = cors_state.preflight_requests;
  stats->allowed_requests = cors_state.allowed_requests;
  stats->rejected_requests = cors_state.rejected_requests;
  stats->configured_origins = cors_state.origin_count;
  stats->allow_all_origins = cors_state.allow_all_origins;
}

void cors_reset_stats(void) {
  if (!cors_state.initialized)
    return;

  cors_state.total_requests = 0;
  cors_state.preflight_requests = 0;
  cors_state.allowed_requests = 0;
  cors_state.rejected_requests = 0;
}
