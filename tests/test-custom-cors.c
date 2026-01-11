#include "ecewo.h"
#include "ecewo-mock.h"
#include "ecewo-cors.h"
#include "tester.h"
#include <string.h>

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

    free_request(&res);
    RETURN_OK();
}

void handler_cors_test(Req *req, Res *res) {
    send_text(res, 200, "CORS OK");
}

void setup_all_routes(void) {
  get("/api/data", handler_cors_test);
}

static const char *allowed_origins[] = {
  "http://localhost:3000",
  "http://example.com"
};

static const Cors custom_cors = {
  .allowed_origins = allowed_origins,
  .allowed_origins_count = 2,
  .allowed_methods = "GET, POST",
  .allowed_headers = "Content-Type, Authorization",
  .allow_credentials = true,
  .exposed_headers = "X-Custom-Header",
  .max_age = 600
};


int main(void) {
  if (mock_init(setup_all_routes) != 0) {
    printf("ERROR: Failed to initialize mock server\n");
    return 1;
  }

  if (!cors_init(&custom_cors)) {
    printf("ERROR: Failed to initialize custom CORS\n");
    mock_cleanup();
    return 1;
  }
  
  RUN_TEST(test_cors_custom_allowed_origin);
  RUN_TEST(test_cors_custom_disallowed_origin);
  RUN_TEST(test_cors_custom_preflight);
  cors_cleanup();
  mock_cleanup();

  return 0;
}
