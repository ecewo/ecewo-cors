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

#include "ecewo-cors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORS_DEFAULT_METHODS "GET, POST, PUT, DELETE, PATCH, OPTIONS"
#define CORS_DEFAULT_HEADERS "Content-Type, Authorization, X-Requested-With"
#define CORS_DEFAULT_MAX_AGE 3600

// ---------------------------------------------------------------------------
// Configuration builder (heap-backed; lifetime ends at install or free).
// ---------------------------------------------------------------------------

typedef struct config_origin_s {
  char *origin;
  struct config_origin_s *next;
} config_origin_t;

struct ecewo_cors_config_s {
  config_origin_t *origins;
  int origin_count;

  char *methods;
  char *allowed_headers;
  char *exposed_headers;

  bool credentials;
  int max_age;
};

// ---------------------------------------------------------------------------
// Installed state (lives in the app arena, owned by the app).
// ---------------------------------------------------------------------------

typedef struct cors_origin_s {
  char *origin;
  struct cors_origin_s *next;
} cors_origin_t;

typedef struct cors_state_s {
  ecewo_arena_t *arena;

  cors_origin_t *origins;
  cors_origin_t *origins_tail;
  int origin_count;
  bool allow_all;

  const char *methods;
  const char *allowed_headers;
  const char *exposed_headers;
  const char *max_age_str;

  bool credentials;
  int max_age;

  uint64_t total_requests;
  uint64_t preflight_requests;
  uint64_t allowed_requests;
  uint64_t rejected_requests;
} cors_state_t;

// Address of this static is used as the per-app data key. Using a file-static
// guarantees uniqueness across plugins without coordination.
static int cors_state_key;

static cors_state_t *cors_state_for(const ecewo_app_t *app) {
  if (!app)
    return NULL;
  return (cors_state_t *)ecewo_get_app_data(app, &cors_state_key);
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

static char *xstrdup(const char *s) {
  if (!s)
    return NULL;
  size_t n = strlen(s);
  char *out = malloc(n + 1);
  if (!out)
    return NULL;
  memcpy(out, s, n + 1);
  return out;
}

static int replace_str(char **slot, const char *value) {
  if (!slot)
    return -1;
  if (!value) {
    free(*slot);
    *slot = NULL;
    return 0;
  }
  char *copy = xstrdup(value);
  if (!copy)
    return -1;
  free(*slot);
  *slot = copy;
  return 0;
}

ecewo_cors_config_t *ecewo_cors_config_new(void) {
  ecewo_cors_config_t *c = calloc(1, sizeof(*c));
  if (!c)
    return NULL;
  c->max_age = CORS_DEFAULT_MAX_AGE;
  return c;
}

void ecewo_cors_config_free(ecewo_cors_config_t *config) {
  if (!config)
    return;
  config_origin_t *node = config->origins;
  while (node) {
    config_origin_t *next = node->next;
    free(node->origin);
    free(node);
    node = next;
  }
  free(config->methods);
  free(config->allowed_headers);
  free(config->exposed_headers);
  free(config);
}

int ecewo_cors_config_add_origin(ecewo_cors_config_t *config, const char *origin) {
  if (!config || !origin)
    return -1;

  for (config_origin_t *n = config->origins; n; n = n->next) {
    if (strcmp(n->origin, origin) == 0)
      return 0;
  }

  config_origin_t *node = malloc(sizeof(*node));
  if (!node)
    return -1;
  node->origin = xstrdup(origin);
  if (!node->origin) {
    free(node);
    return -1;
  }
  node->next = NULL;

  if (!config->origins) {
    config->origins = node;
  } else {
    config_origin_t *tail = config->origins;
    while (tail->next)
      tail = tail->next;
    tail->next = node;
  }
  config->origin_count++;
  return 0;
}

int ecewo_cors_config_set_methods(ecewo_cors_config_t *config, const char *methods) {
  if (!config)
    return -1;
  return replace_str(&config->methods, methods);
}

int ecewo_cors_config_set_allowed_headers(ecewo_cors_config_t *config, const char *headers) {
  if (!config)
    return -1;
  return replace_str(&config->allowed_headers, headers);
}

int ecewo_cors_config_set_exposed_headers(ecewo_cors_config_t *config, const char *headers) {
  if (!config)
    return -1;
  if (headers && *headers == '\0')
    headers = NULL;
  return replace_str(&config->exposed_headers, headers);
}

void ecewo_cors_config_set_credentials(ecewo_cors_config_t *config, bool credentials) {
  if (!config)
    return;
  config->credentials = credentials;
}

void ecewo_cors_config_set_max_age(ecewo_cors_config_t *config, int max_age) {
  if (!config)
    return;
  config->max_age = (max_age > 0) ? max_age : CORS_DEFAULT_MAX_AGE;
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

static bool origin_in_state(const cors_state_t *state, const char *origin) {
  for (const cors_origin_t *n = state->origins; n; n = n->next) {
    if (strcmp(n->origin, origin) == 0)
      return true;
  }
  return false;
}

static int state_add_origin(cors_state_t *state, const char *origin) {
  if (!origin)
    return -1;

  if (origin_in_state(state, origin))
    return 0;

  cors_origin_t *node = ecewo_alloc(state->arena, sizeof(*node));
  if (!node)
    return -1;
  node->origin = ecewo_strdup(state->arena, origin);
  if (!node->origin)
    return -1;
  node->next = NULL;

  if (state->origins_tail) {
    state->origins_tail->next = node;
    state->origins_tail = node;
  } else {
    state->origins = node;
    state->origins_tail = node;
  }
  state->origin_count++;

  if (strcmp(origin, "*") == 0)
    state->allow_all = true;

  return 0;
}

static int state_remove_origin(cors_state_t *state, const char *origin) {
  if (!origin)
    return -1;

  cors_origin_t *prev = NULL;
  cors_origin_t *node = state->origins;
  while (node) {
    if (strcmp(node->origin, origin) == 0) {
      if (prev)
        prev->next = node->next;
      else
        state->origins = node->next;
      if (state->origins_tail == node)
        state->origins_tail = prev;
      if (strcmp(node->origin, "*") == 0)
        state->allow_all = false;
      state->origin_count--;
      // Memory remains in the app arena; arenas don't free individual entries.
      return 0;
    }
    prev = node;
    node = node->next;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

static void cors_middleware(ecewo_request_t *req, ecewo_response_t *res, ecewo_next_t next) {
  ecewo_app_t *app = ecewo_req_app(req);
  cors_state_t *state = cors_state_for(app);
  if (!state) {
    next(req, res);
    return;
  }

  state->total_requests++;

  const char *request_origin = ecewo_header_get(req, "Origin");
  const char *method = ecewo_req_method(req);

  bool is_preflight = method && strcmp(method, "OPTIONS") == 0;

  if (is_preflight) {
    state->preflight_requests++;

    bool origin_ok = state->allow_all || (request_origin && origin_in_state(state, request_origin));

    if (request_origin && !origin_ok) {
      state->rejected_requests++;
      ecewo_send_text(res, ECEWO_FORBIDDEN, "CORS: Origin not allowed");
      return;
    }

    state->allowed_requests++;

    if (state->allow_all) {
      ecewo_header_set(res, "Access-Control-Allow-Origin", "*");
    } else if (request_origin) {
      ecewo_header_set(res, "Access-Control-Allow-Origin", request_origin);
      ecewo_header_set(res, "Vary", "Origin");
    }

    ecewo_header_set(res, "Access-Control-Allow-Methods", state->methods);
    ecewo_header_set(res, "Access-Control-Allow-Headers", state->allowed_headers);

    if (state->credentials)
      ecewo_header_set(res, "Access-Control-Allow-Credentials", "true");

    ecewo_header_set(res, "Access-Control-Max-Age", state->max_age_str);

    ecewo_send(res, ECEWO_NO_CONTENT, NULL, 0);
    return;
  }

  bool added = false;

  if (state->allow_all) {
    ecewo_header_set(res, "Access-Control-Allow-Origin", "*");
    added = true;
    state->allowed_requests++;
  } else if (request_origin && origin_in_state(state, request_origin)) {
    ecewo_header_set(res, "Access-Control-Allow-Origin", request_origin);
    ecewo_header_set(res, "Vary", "Origin");
    added = true;
    state->allowed_requests++;
  } else if (request_origin) {
    state->rejected_requests++;
  }

  if (added) {
    if (state->credentials)
      ecewo_header_set(res, "Access-Control-Allow-Credentials", "true");
    if (state->exposed_headers)
      ecewo_header_set(res, "Access-Control-Expose-Headers", state->exposed_headers);
  }

  next(req, res);
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

static char *arena_strdup_or_default(ecewo_arena_t *arena, const char *src, const char *fallback) {
  return ecewo_strdup(arena, src ? src : fallback);
}

int ecewo_cors_install(ecewo_app_t *app, ecewo_cors_config_t *config) {
  if (!app) {
    ecewo_cors_config_free(config);
    return -1;
  }

  if (cors_state_for(app)) {
    fprintf(stderr, "[ecewo-cors] CORS is already installed on this app\n");
    ecewo_cors_config_free(config);
    return -1;
  }

  ecewo_arena_t *arena = ecewo_app_arena(app);
  if (!arena) {
    ecewo_cors_config_free(config);
    return -1;
  }

  cors_state_t *state = ecewo_alloc(arena, sizeof(*state));
  if (!state) {
    ecewo_cors_config_free(config);
    return -1;
  }
  memset(state, 0, sizeof(*state));
  state->arena = arena;
  state->max_age = CORS_DEFAULT_MAX_AGE;

  bool have_user_origins = config && config->origins;
  if (have_user_origins) {
    for (config_origin_t *n = config->origins; n; n = n->next) {
      if (state_add_origin(state, n->origin) != 0) {
        fprintf(stderr, "[ecewo-cors] Failed to register origin '%s'\n", n->origin);
        ecewo_cors_config_free(config);
        return -1;
      }
    }
  } else {
    if (state_add_origin(state, "*") != 0) {
      ecewo_cors_config_free(config);
      return -1;
    }
  }

  bool credentials = config ? config->credentials : false;
  if (credentials && state->allow_all) {
    fprintf(stderr,
            "[ecewo-cors] ERROR: credentials=true cannot be combined with origin '*' "
            "(violates the CORS specification). Specify explicit origins.\n");
    ecewo_cors_config_free(config);
    return -1;
  }
  state->credentials = credentials;

  state->methods = arena_strdup_or_default(arena,
                                           config ? config->methods : NULL, CORS_DEFAULT_METHODS);
  state->allowed_headers = arena_strdup_or_default(arena,
                                                   config ? config->allowed_headers : NULL, CORS_DEFAULT_HEADERS);
  state->exposed_headers = (config && config->exposed_headers)
      ? ecewo_strdup(arena, config->exposed_headers)
      : NULL;
  if (!state->methods || !state->allowed_headers || (config && config->exposed_headers && !state->exposed_headers)) {
    fprintf(stderr, "[ecewo-cors] arena allocation failed during install\n");
    ecewo_cors_config_free(config);
    return -1;
  }

  // Pre-format max-age so the middleware allocates nothing per request.
  int max_age = (config && config->max_age > 0) ? config->max_age : CORS_DEFAULT_MAX_AGE;
  state->max_age = max_age;
  state->max_age_str = ecewo_sprintf(arena, "%d", max_age);
  if (!state->max_age_str) {
    fprintf(stderr, "[ecewo-cors] arena allocation failed during install\n");
    ecewo_cors_config_free(config);
    return -1;
  }

  ecewo_set_app_data(app, &cors_state_key, state);
  ecewo_use(app, NULL, cors_middleware);

  ecewo_cors_config_free(config);
  return 0;
}

// ---------------------------------------------------------------------------
// Runtime origin management
// ---------------------------------------------------------------------------

int ecewo_cors_add_origin(ecewo_app_t *app, const char *origin) {
  cors_state_t *state = cors_state_for(app);
  if (!state || !origin)
    return -1;
  if (state_add_origin(state, origin) != 0)
    return -1;
  if (state->credentials && state->allow_all) {
    // Roll back; this combination is illegal.
    state_remove_origin(state, "*");
    fprintf(stderr,
            "[ecewo-cors] Refusing to add '*' while credentials=true is set\n");
    return -1;
  }
  return 0;
}

int ecewo_cors_remove_origin(ecewo_app_t *app, const char *origin) {
  cors_state_t *state = cors_state_for(app);
  if (!state || !origin)
    return -1;
  return state_remove_origin(state, origin);
}

bool ecewo_cors_is_origin_allowed(const ecewo_app_t *app, const char *origin) {
  const cors_state_t *state = cors_state_for(app);
  if (!state || !origin)
    return false;
  if (state->allow_all)
    return true;
  return origin_in_state(state, origin);
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

uint64_t ecewo_cors_stat_total(const ecewo_app_t *app) {
  const cors_state_t *s = cors_state_for(app);
  return s ? s->total_requests : 0;
}

uint64_t ecewo_cors_stat_preflight(const ecewo_app_t *app) {
  const cors_state_t *s = cors_state_for(app);
  return s ? s->preflight_requests : 0;
}

uint64_t ecewo_cors_stat_allowed(const ecewo_app_t *app) {
  const cors_state_t *s = cors_state_for(app);
  return s ? s->allowed_requests : 0;
}

uint64_t ecewo_cors_stat_rejected(const ecewo_app_t *app) {
  const cors_state_t *s = cors_state_for(app);
  return s ? s->rejected_requests : 0;
}

int ecewo_cors_stat_origin_count(const ecewo_app_t *app) {
  const cors_state_t *s = cors_state_for(app);
  return s ? s->origin_count : 0;
}

bool ecewo_cors_stat_allow_all(const ecewo_app_t *app) {
  const cors_state_t *s = cors_state_for(app);
  return s ? s->allow_all : false;
}

void ecewo_cors_reset_stats(ecewo_app_t *app) {
  cors_state_t *s = cors_state_for(app);
  if (!s)
    return;
  s->total_requests = 0;
  s->preflight_requests = 0;
  s->allowed_requests = 0;
  s->rejected_requests = 0;
}
