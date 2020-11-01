#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include "../includes/tests.h"
#include "../includes/request.h"

#define FIXBUF(b, data)                 \
    buffer_init(&(b), N(data), (data)); \
    buffer_write_adv(&(b), N(data))

START_TEST(test_request_connect_fqdn)
{
    struct request request;
    request_parser request_parser = {
        .request = &request,
    };
    request_parser_init(&request_parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x03, 0x0f,
        0x77, 0x77, 0x77, 0x2e, 0x69,
        0x74, 0x62, 0x61, 0x2e, 0x65,
        0x64, 0x75, 0x2e, 0x61, 0x72,
        0x00, 0x50};
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    request_consume(&b, &request_parser, &errored);

    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(cmd_connect, request.cmd);
    ck_assert_uint_eq(domainname_type, request.dest_addr_type);
    ck_assert_str_eq("www.itba.edu.ar", request.dest_addr.fqdn);
    ck_assert_uint_eq(htons(80), request.dest_port);
}
END_TEST

START_TEST(test_request_connect_ipv4)
{
    struct request request;
    request_parser request_parser = {
        .request = &request,
    };
    request_parser_init(&request_parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x01, 0x7f,
        0x00, 0x00, 0x01, 0x1F, 0x90};
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    request_consume(&b, &request_parser, &errored);

    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(cmd_connect, request.cmd);
    ck_assert_uint_eq(ipv4_type, request.dest_addr_type);
    char rst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &request.dest_addr.ipv4.sin_addr, rst, INET_ADDRSTRLEN);
    ck_assert_str_eq("127.0.0.1", inet_ntoa(request.dest_addr.ipv4.sin_addr));
    ck_assert_uint_eq(htons(8080), request.dest_port);
}
END_TEST

START_TEST(test_request_connect_ipv6)
{
    struct request request;
    request_parser request_parser = {
        .request = &request,
    };
    request_parser_init(&request_parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01,
        0x23, 0x82};
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    request_consume(&b, &request_parser, &errored);

    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(cmd_connect, request.cmd);
    ck_assert_uint_eq(ipv6_type, request.dest_addr_type);
    char rst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &request.dest_addr.ipv6.sin6_addr, rst, INET6_ADDRSTRLEN);
    ck_assert_str_eq("::1", rst);
    ck_assert_uint_eq(htons(9090), request.dest_port);
}
END_TEST

START_TEST(test_invalid_cmd)
{
    struct request request;
    request_parser request_parser = {
        .request = &request,
    };
    request_parser_init(&request_parser);
    uint8_t data[] = {
        0x05, 0x05, 0x00, 0x01, 0x7f,
        0x00, 0x00, 0x01, 0x1F, 0x90};
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    request_consume(&b, &request_parser, &errored);

    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(request_error_usupported_cmd, request_parser.state);
}
END_TEST

START_TEST(test_invalid_atyp)
{
    struct request request;
    request_parser request_parser = {
        .request = &request,
    };
    request_parser_init(&request_parser);
    uint8_t data[] = {
        0x05, 0x02, 0x00, 0x02, 0x7f,
        0x00, 0x00, 0x01, 0x1F, 0x90};
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    request_consume(&b, &request_parser, &errored);

    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(request_error_usupported_atyp, request_parser.state);
}
END_TEST

START_TEST(test_request_unsupported_version)
{
    struct request request;
    request_parser request_parser = {
        .request = &request,
    };
    request_parser_init(&request_parser);
    uint8_t data[] = {
        0x04,
    };
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum request_state st = request_consume(&b, &request_parser, &errored);

    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(request_error_unsupported_version, st);
}
END_TEST

START_TEST(test_request_connect_multiple_requests)
{
    struct request request;
    request_parser request_parser = {
        .request = &request,
    };
    request_parser_init(&request_parser);
    uint8_t data[] = {
        0x05,
        0x01,
        0x00,
        0x03,
        0x0f,
        0x77,
        0x77,
        0x77,
        0x2e,
        0x69,
        0x74,
        0x62,
        0x61,
        0x2e,
        0x65,
        0x64,
        0x75,
        0x2e,
        0x61,
        0x72,
        0x00,
        0x50,
        0x05,
        0x01,
        0x00,
        0x03,
        0x0f,
        0x77,
        0x77,
        0x77,
        0x2e,
        0x69,
        0x74,
        0x62,
        0x61,
        0x2e,
        0x65,
        0x64,
        0x75,
        0x2e,
        0x61,
        0x72,
        0x00,
        0x50,
    };
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    request_consume(&b, &request_parser, &errored);

    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(cmd_connect, request.cmd);
    ck_assert_uint_eq(domainname_type, request.dest_addr_type);
    ck_assert_str_eq("www.itba.edu.ar", request.dest_addr.fqdn);
    ck_assert_uint_eq(htons(80), request.dest_port);

    errored = false;
    memset(&request, 0, sizeof(request));
    request_parser_init(&request_parser);

    request_consume(&b, &request_parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(cmd_connect, request.cmd);
    ck_assert_uint_eq(domainname_type, request.dest_addr_type);
    ck_assert_str_eq("www.itba.edu.ar", request.dest_addr.fqdn);
    ck_assert_uint_eq(htons(80), request.dest_port);
}
END_TEST

Suite *
suite(void)
{
    Suite *s = suite_create("request");

    // Normal usage for fqdn test case
    TCase *tc_connect_fqdn = tcase_create("request_connect_fqdn");
    tcase_add_test(tc_connect_fqdn, test_request_connect_fqdn);
    suite_add_tcase(s, tc_connect_fqdn);

    // Normal usage for ipv4 address test case
    TCase *tc_connect_ipv4 = tcase_create("request_connect_ipv4");
    tcase_add_test(tc_connect_ipv4, test_request_connect_ipv4);
    suite_add_tcase(s, tc_connect_ipv4);

    // Normal usage for ipv4 address test case
    TCase *tc_connect_ipv6 = tcase_create("request_connect_ipv6");
    tcase_add_test(tc_connect_ipv6, test_request_connect_ipv6);
    suite_add_tcase(s, tc_connect_ipv6);

    // unsupported version test case
    TCase *tc_connect_unsupp = tcase_create("test_request_unsupported_version");
    tcase_add_test(tc_connect_unsupp, test_request_unsupported_version);
    suite_add_tcase(s, tc_connect_unsupp);

    // multiple request test case
    TCase *tc_multiple_requests = tcase_create("test_request_multiple_requests");
    tcase_add_test(tc_multiple_requests, test_request_connect_multiple_requests);
    suite_add_tcase(s, tc_multiple_requests);

    // Invalid command test case
    TCase *tc_invalid_cmd = tcase_create("test_invalid_cmd");
    tcase_add_test(tc_invalid_cmd, test_invalid_cmd);
    suite_add_tcase(s, tc_invalid_cmd);

    // Invalid address type test case
    TCase *tc_invalid_atyp = tcase_create("test_invalid_atyp");
    tcase_add_test(tc_invalid_atyp, test_invalid_atyp);
    suite_add_tcase(s, tc_invalid_atyp);

    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(suite());
    int number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}