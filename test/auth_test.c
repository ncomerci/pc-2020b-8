#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include "../includes/buffer.h"
#include "../includes/tests.h"
#include "../includes/auth.h"

#define FIXBUF(b, data)                 \
    buffer_init(&(b), N(data), (data)); \
    buffer_write_adv(&(b), N(data))


START_TEST(test_auth_normal)
{
    struct auth_parser parser;

    auth_parser_init(&parser);

    uint8_t data[] = {
        0x01, // auth version
        0x04, // ulen
        0x67, 0x65, 0x72, 0x6f, //user (gero)
        0x04, // passlen
        0x31, 0x32, 0x33, 0x34, //pass
    };
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum auth_state st = auth_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_str_eq("gero", parser.usr->uname);
    ck_assert_str_eq("1234", parser.pass->passwd);
    ck_assert_uint_eq(auth_done, st);
}
END_TEST

START_TEST(test_auth_unsupported_version)
{
    struct auth_parser parser;

    auth_parser_init(&parser);

    uint8_t data[] = {
        0x04, // auth version
        0x04, // ulen
        0x67, 0x65, 0x72, 0x6f, //user (gero)
        0x04, // passlen
        0x31, 0x32, 0x33, 0x34, //pass
    };
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum auth_state st = auth_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(auth_error_unsupported_version, st);
}
END_TEST


START_TEST(test_auth_invalid_ulen)
{
    struct auth_parser parser;

    auth_parser_init(&parser);

    uint8_t data[] = {
        0x01, // auth version
        0x00, // ulen
        0x67, 0x65, 0x72, 0x6f, //user (gero)
        0x04, // passlen
        0x31, 0x32, 0x33, 0x34, //pass
    };
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum auth_state st = auth_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(auth_error_invalid_ulen, st);
}
END_TEST

START_TEST(test_auth_invalid_plen)
{
    struct auth_parser parser;

    auth_parser_init(&parser);

    uint8_t data[] = {
        0x01, // auth version
        0x04, // ulen
        0x67, 0x65, 0x72, 0x6f, //user (gero)
        0x00, // passlen
        0x31, 0x32, 0x33, 0x34, //pass
    };
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    enum auth_state st = auth_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(auth_error_invalid_plen, st);
}
END_TEST




Suite *
suite(void)
{
    Suite *s = suite_create("auth");

    // Normal usage test case
    TCase *tc_normal = tcase_create("auth_normal");
    tcase_add_test(tc_normal, test_auth_normal);
    suite_add_tcase(s, tc_normal);

    // Unsupported socks version test case
    TCase *tc_unsupported_version = tcase_create("auth_unsupported_version");
    tcase_add_test(tc_unsupported_version, test_auth_unsupported_version);
    suite_add_tcase(s, tc_unsupported_version);

    // Invalid username length test case
    TCase *tc_auth_invalid_ulen = tcase_create("auth_invalid_ulen");
    tcase_add_test(tc_auth_invalid_ulen, test_auth_invalid_ulen);
    suite_add_tcase(s, tc_auth_invalid_ulen);

    // Invalid password length test case
    TCase *tc_auth_invalid_plen = tcase_create("auth_invalid_plen");
    tcase_add_test(tc_auth_invalid_plen, test_auth_invalid_plen);
    suite_add_tcase(s, tc_auth_invalid_plen);

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