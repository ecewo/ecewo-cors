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

#include "ecewo.h"
#include "ecewo-mock.h"
#include "ecewo-cors.h"
#include "tester.h"
#include <string.h>
#include <stdlib.h>

static void handler_cors_test(ecewo_request_t *req, ecewo_response_t *res) {
  (void)req;
  ecewo_send_text(res, 200, "CORS OK");
}

int test_cors_custom_allowed_origin(void) {
  MockHeaders headers[] = {
    { "Origin", "http://localhost:3000" }
  };

  MockParams params = {
    .method = MOCK_GET,
    .path = "/api/data",
    .body = NULL,
    .headers = headers,
    .header_count = 1
  };

  MockResponse res = request(&params);

  ASSERT_EQ(200, res.status_code);
  ASSERT_EQ_STR("CORS OK", res.body);
  ASSERT_EQ_STR("http://localhost:3000", mock_get_header(&res, "Access-Control-Allow-Origin"));
  ASSERT_EQ_STR("Origin", mock_get_header(&res, "Vary"));
  ASSERT_EQ_STR("true", mock_get_header(&res, "Access-Control-Allow-Credentials"));
  ASSERT_EQ_STR("X-Custom-Header", mock_get_header(&res, "Access-Control-Expose-Headers"));

  free_request(&res);
  RETURN_OK();
}

int test_cors_custom_disallowed_origin(void) {
  MockHeaders headers[] = {
    { "Origin", "http://notallowed.com" }
  };

  MockParams params = {
    .method = MOCK_GET,
    .path = "/api/data",
    .body = NULL,
    .headers = headers,
    .header_count = 1
  };

  MockResponse res = request(&params);

  ASSERT_EQ(200, res.status_code);
  ASSERT_NULL(mock_get_header(&res, "Access-Control-Allow-Origin"));

  free_request(&res);
  RETURN_OK();
}

int test_cors_custom_preflight(void) {
  MockHeaders headers[] = {
    { "Origin", "http://example.com" },
    { "Access-Control-Request-Method", "POST" },
    { "Access-Control-Request-Headers", "Content-Type" }
  };

  MockParams params = {
    .method = MOCK_OPTIONS,
    .path = "/api/data",
    .body = NULL,
    .headers = headers,
    .header_count = 3
  };

  MockResponse res = request(&params);

  ASSERT_EQ(204, res.status_code);
  ASSERT_EQ_STR("http://example.com", mock_get_header(&res, "Access-Control-Allow-Origin"));
  ASSERT_EQ_STR("true", mock_get_header(&res, "Access-Control-Allow-Credentials"));
  ASSERT_EQ_STR("Content-Type, Authorization", mock_get_header(&res, "Access-Control-Allow-Headers"));
  ASSERT_EQ_STR("GET, POST", mock_get_header(&res, "Access-Control-Allow-Methods"));
  ASSERT_EQ_STR("600", mock_get_header(&res, "Access-Control-Max-Age"));

  free_request(&res);
  RETURN_OK();
}

int test_cors_preflight_disallowed(void) {
  MockHeaders headers[] = {
    { "Origin", "http://notallowed.com" },
    { "Access-Control-Request-Method", "POST" }
  };

  MockParams params = {
    .method = MOCK_OPTIONS,
    .path = "/api/data",
    .body = NULL,
    .headers = headers,
    .header_count = 2
  };

  MockResponse res = request(&params);

  ASSERT_EQ(403, res.status_code);
  ASSERT_NULL(mock_get_header(&res, "Access-Control-Allow-Origin"));

  free_request(&res);
  RETURN_OK();
}

static void setup_routes(ecewo_app_t *app) {
  ecewo_cors_config_t *cfg = ecewo_cors_config_new();
  if (!cfg) {
    fprintf(stderr, "ERROR: ecewo_cors_config_new failed\n");
    exit(1);
  }

  if (ecewo_cors_config_add_origin(cfg, "http://localhost:3000") != 0 || ecewo_cors_config_add_origin(cfg, "http://example.com") != 0 || ecewo_cors_config_set_methods(cfg, "GET, POST") != 0 || ecewo_cors_config_set_allowed_headers(cfg, "Content-Type, Authorization") != 0 || ecewo_cors_config_set_exposed_headers(cfg, "X-Custom-Header") != 0) {
    fprintf(stderr, "ERROR: ecewo_cors_config setup failed\n");
    exit(1);
  }
  ecewo_cors_config_set_credentials(cfg, true);
  ecewo_cors_config_set_max_age(cfg, 600);

  if (ecewo_cors_install(app, cfg) != 0) {
    fprintf(stderr, "ERROR: ecewo_cors_install (custom) failed\n");
    exit(1);
  }

  ECEWO_GET(app, "/api/data", handler_cors_test);
  ECEWO_POST(app, "/api/data", handler_cors_test);
}

int main(void) {
  if (mock_init(setup_routes) != 0) {
    printf("ERROR: Failed to initialize mock server\n");
    return 1;
  }

  RUN_TEST(test_cors_custom_allowed_origin);
  RUN_TEST(test_cors_custom_disallowed_origin);
  RUN_TEST(test_cors_custom_preflight);
  RUN_TEST(test_cors_preflight_disallowed);

  mock_cleanup();
  return 0;
}
