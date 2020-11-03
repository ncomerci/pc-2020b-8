#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include "../includes/buffer.h"
#include "../includes/tests.h"
#include "../includes/auth.h"

// solve

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
        0x01, 0x02, 0x03, 0x04 //pass
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

Suite *
suite(void)
{
    Suite *s = suite_create("auth");

    // Normal usage test case
    TCase *tc_normal = tcase_create("auth_normal");
    tcase_add_test(tc_normal, test_auth_normal);
    suite_add_tcase(s, tc_normal);

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