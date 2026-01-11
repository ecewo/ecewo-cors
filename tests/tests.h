#ifndef ECEWO_COOKIE_TESTS
#define ECEWO_COOKIE_TESTS

#include "ecewo.h"

void handler_cors_test(Req *req, Res *res);

int test_cors_preflight_request(void);
int test_cors_simple_request(void);
int test_cors_no_origin(void);

int test_cors_custom_allowed_origin(void);
int test_cors_custom_disallowed_origin(void);
int test_cors_custom_preflight(void);

#endif