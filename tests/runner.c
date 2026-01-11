#include "ecewo-mock.h"
#include "ecewo-cors.h"
#include "tests.h"
#include "tester.h"

void setup_all_routes(void) {
  get("/api/data", handler_cors_test);
  options("/api/data", handler_cors_test); // TODO: Remove it, users shouldn't register options manually
}

static const char *allowed_origins[] = {
  "http://localhost:3000",
  "http://allowed.com"
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
  // Default CORS
  if (!cors_init(NULL)) {
    printf("ERROR: Failed to initialize default CORS\n");
    mock_cleanup();
    return 1;
  }

  if (mock_init(setup_all_routes) != 0) {
    printf("ERROR: Failed to initialize mock server\n");
    return 1;
  }

  RUN_TEST(test_cors_simple_request);
  RUN_TEST(test_cors_no_origin);
  cors_cleanup();
  mock_cleanup();

  if (!cors_init(&custom_cors)) {
    printf("ERROR: Failed to initialize custom CORS\n");
    mock_cleanup();
    return 1;
  }

  if (mock_init(setup_all_routes) != 0) {
    printf("ERROR: Failed to initialize mock server\n");
    return 1;
  }
  
  RUN_TEST(test_cors_custom_allowed_origin);
  RUN_TEST(test_cors_custom_disallowed_origin);
  RUN_TEST(test_cors_custom_preflight);
  cors_cleanup();
  mock_cleanup();

  return 0;
}
