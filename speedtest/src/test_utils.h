/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of utility macros & functions for use in tests.
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

/**
 * Puts a wrapper around the given code to time the test repeat.
 * Note: Only for use in the speed test suite!
 *
 * @param[in] subtest   the number of the subtest
 * @param[in] repeat_nr the number of the test repeat
 * @param[in] code the  code to run for the test repeat
 */
#define TIME_TEST_REPEAT(subtest, repeat_nr, code) \
        start_speed_subtest_timing(); \
        code; \
        stop_speed_subtest_timing(subtest, repeat_nr);

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Prints the message at the start of the test suite and starts its timer.
     *
     * @param[in] suite the name of the test suite
     */
    void start_test_suite(const char *suite);

    /**
     * Prints the message at the start of a test and starts its timer.
     *
     * @param[in] test the name of the test
     */
    void start_test(const char *test);

    /**
     * Prints the message at the end of a test and returns the test status.
     *
     * @param[in] error NULL in case of a successful test, otherwise the error
     *                  to be include in the test failure message
     * @return __0__ in case of success, __1__ in case of failure
     */
    unsigned int end_test(const char *error);

    /**
     * Prints the message at the end of the test suite.
     * @param[in] nr_failed the number of failed tests (0 for success)
     */
    void end_test_suite(const unsigned int nr_failed);

    /**
     * Prints the message at the start of the speed test suite and starts its
     * timer.
     *
     * @param[in] suite    the name of the test suite
     * @param[in] names    array with the names of the subtests
     * @param[in] subtests the number of subtests
     * @param[in] repeats  the number of times each speed test is repeated
     */
    void start_speed_test_suite(const char *suite, const char *names[], const unsigned int subtests, const unsigned int repeats);

    /**
     * Prints the message at the start of a speed test and starts its timer.
     *
     * @param[in] test the name of the test
     */
    void start_speed_test(const char *test);

    /**
     * Starts the cpu cycle timing of a single test repeat of a subtest.
     */
    void start_speed_subtest_timing(void);

    /**
     * Stops the cpu cycle timing of a single speed subtest test repeat.
     *
     * @param[in] subtest the subtest number
     * @param[in] repeat_nr the number of the test repeat
     */
    void stop_speed_subtest_timing(const unsigned int subtest, const unsigned int repeat_nr);

    /**
     * Administrates the completion of a speed subtests.
     *
     * @param[in] subtest number of the subtest.
     * @param[in] test_name name of the subtest.
     */
    void done_speed_test(const unsigned int subtest, char *test_name);

    /**
     * Prints the message at the end of the speed test suite.
     * @param[in] summary pointer to a string describing the summary, or NULL if
     *                    no summary should be printed
     */
    void end_speed_test_suite(const char *summary);

#ifdef __cplusplus
}
#endif

#endif /* TEST_UTILS_H */
