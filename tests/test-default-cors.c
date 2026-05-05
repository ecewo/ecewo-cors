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

static void handler_cors_test(ecewo_request_t *req, ecewo_response_t *res) {
  (void)req;
  ecewo_send_text(res, 200, "CORS OK");
}

int test_cors_preflight_request(void) {
  MockHeaders headers[] = {
    { "Origin", "http://localhost:3000" },
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

  ASSERT_EQ(204, res.status_code);
  ASSERT_EQ_STR("*", mock_get_header(&res, "Access-Control-Allow-Origin"));

  free_request(&res);
  RETURN_OK();
}

int test_cors_simple_request(void) {
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
  ASSERT_EQ_STR("*", mock_get_header(&res, "Access-Control-Allow-Origin"));

  free_request(&res);
  RETURN_OK();
}

int test_cors_no_origin(void) {
  MockParams params = {
    .method = MOCK_GET,
    .path = "/api/data",
    .body = NULL,
    .headers = NULL,
    .header_count = 0
  };

  MockResponse res = request(&params);

  ASSERT_EQ(200, res.status_code);
  ASSERT_EQ_STR("CORS OK", res.body);

  free_request(&res);
  RETURN_OK();
}

static void setup_routes(ecewo_app_t *app) {
  if (ecewo_cors_install(app, NULL) != 0) {
    fprintf(stderr, "ERROR: ecewo_cors_install (default) failed\n");
    exit(1);
  }

  ECEWO_GET(app, "/api/data", handler_cors_test);
}

int main(void) {
  if (mock_init(setup_routes) != 0) {
    printf("ERROR: Failed to initialize mock server\n");
    return 1;
  }

  RUN_TEST(test_cors_preflight_request);
  RUN_TEST(test_cors_simple_request);
  RUN_TEST(test_cors_no_origin);

  mock_cleanup();
  return 0;
}
