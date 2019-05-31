/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of utility macros & functions for use in tests.
 */

#include "test_utils.h"

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>

/**
 * Determines the current cpu cycle count.
 *
 * @param[in] v the variable to store the result in (must be of type `uint64_t`)
 */
#if defined(__x86_64__)
#define CPU_CYCLE_COUNT(v) __asm__ __volatile__("rdtsc; shlq $32,%%rdx;orq %%rdx,%%rax" : "=a" (v) : : "memory", "%rdx")
#elif defined(__i386__)
unsigned int lo, hi;
#define CPU_CYCLE_COUNT(v)  __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi)); v = ((uint64_t)hi << 32) | lo
#else
#warning Can not run speed tests on non i386 platform
#define CPU_CYCLE_COUNT(v)  v = 0
#endif

/**
 * Flag to indicate NetBeans test framework fluff should be added to the output.
 * The value of this flag is based on the existence of the `NBMAGIC` environment
 * variable. The flag is set in the `start_test_suite` and
 * `start_speed_test_suite` functions.
 */
static unsigned int netbeans;

/** Name of the test suite */
static const char *suite_name;

/** Name of the test */
static const char *test_name;

/** Start time of the test suite */
static clock_t suite_start_time;

/** Start time of the test */
static clock_t test_start_time;

/** The number of sub tests in the speed tests */
static unsigned int nr_subtests;

/** Array with the names of the subtests */
static char **subtest_names;

/** The number of times the tests are repeated in speed tests */
static unsigned int nr_test_repeats;

/** CPU Cycle count at start of an individual speed test */
static uint64_t subtest_cpu_start;

/** Buffer for the cpu timing results per subtest, per test repeat */
static uint64_t **subtest_cpu;

/** Buffer for the average cpu timing results per subtest */
static uint64_t *subtest_cpu_average;

/** Clock count at start of an individual speed test */
static clock_t subtest_clock_start;

/** Buffer for the clock timing results per subtest, per test repeat */
static clock_t **subtest_clock;

/** Buffer for the average cpu timing results per subtest */
static clock_t *subtest_clock_average;

/**
 * Determines the elapsed time in seconds.
 *
 * @param[in] start the start time to calculate the elapsed time from
 * @return the elapsed time
 */
static double elapsed_from(const clock_t start) {
    return (double) (clock() - start) / CLOCKS_PER_SEC;
}

/**
 * Compares two timings.
 * @param[in] a, b  the values to compare
 * @return __1__ if a>b, __0__ if a == b, or <b>-1</b> if a < b
 */
static int compare_timings(const void *a, const void *b) {
    return (*(const uint64_t *) a > *(const uint64_t *) b) - (*(const uint64_t *) a < *(const uint64_t *) b);
}

/**
 * Prints the timing results header.
 */
static void print_timings_header() {
    printf("%30s %9s %9s %9s %9s %9s\n", "Subtest", "Minimum", "Median", "Maximum", "Average", "StdDev");
}

/**
 * Prints the timing results separator line.
 */
static void print_timings_separator() {
    printf("------------------------------ --------- --------- --------- --------- ---------\n");
}

/**
 * Prints the cpu timing results.
 * @param[in] test               the name of the test
 * @param[in] min, med, max, avg the minimum, median, maximum, average number of cpu cycles the test cost
 * @param[in] stdev              the standard deviation of the measured cpu cycles in each test repeat
 */
static void print_cpu_timings(const char *test, const uint64_t min, const uint64_t med, const uint64_t max, const uint64_t avg, const double stdev) {
    printf("CPU %26s", test);
    printf(" %9" PRIu64, min);
    printf(" %9" PRIu64, med);
    printf(" %9" PRIu64, max);
    printf(" %9" PRIu64, avg);
    if (stdev > 0) printf(" %9.0f", stdev);
    printf("\n");
}

/**
 * Prints the clock timing results.
 * @param[in] test               the name of the test
 * @param[in] min, med, max, avg the minimum, median, maximum, average number of clock ticks the test cost
 * @param[in] stdev              the standard deviation of the measured clock ticks in each test repeat
 */
static void print_clock_timings(const char *test, const clock_t min, const clock_t med, const clock_t max, const clock_t avg, const double stdev) {
    printf("ms  %26s", test);
    printf(" %9.3f", min / (CLOCKS_PER_SEC / 1000.0));
    printf(" %9.3f", med / (CLOCKS_PER_SEC / 1000.0));
    printf(" %9.3f", max / (CLOCKS_PER_SEC / 1000.0));
    printf(" %9.3f", avg / (CLOCKS_PER_SEC / 1000.0));
    if (stdev > 0) printf(" %9.3f", stdev / (CLOCKS_PER_SEC / 1000.0));
    printf("\n");
}

void start_test_suite(const char *suite) {
    static const char *stars = "********************************************************************************";
    static const char *title = "Running test suite";
    const size_t title_len = 2 + strlen(title) + 2 + strlen(suite);
    netbeans = getenv("NBMAGIC") != NULL;
    suite_name = suite;
    if (netbeans) printf("%%SUITE_STARTING%% %s\n", suite_name);
    printf("%s\n", stars);
    printf("* %s: %s", title, suite_name);
    if (title_len < 80)
        printf("%*s\n", (int) (80 - title_len), "*");
    else
        printf("\n");
    printf("%s\n", stars);
    if (netbeans) printf("%%SUITE_STARTED%%\n");
    printf("\n");
    suite_start_time = clock();
}

void start_test(const char *test) {
    test_name = test;
    printf("Running test %s\n", test_name);
    if (netbeans) printf("%%TEST_STARTED%% %s (%s)\n", test_name, suite_name);
    test_start_time = clock();
}

unsigned int end_test(const char *error) {
    if (error != NULL) {
        printf("FAILED test %s: %s\n", test_name, error);
        if (netbeans) printf("%%TEST_FAILED%% time=%.3f testname=%s (%s) message=%s\n", elapsed_from(test_start_time), test_name, suite_name, error);
    } else {
        printf("Successfully finished test %s\n", test_name);
    }
    if (netbeans) printf("%%TEST_FINISHED%% time=%.3f %s (%s)\n", elapsed_from(test_start_time), test_name, suite_name);
    printf("\n");
    return error != NULL;
}

void end_test_suite(const unsigned int nr_failed) {
    if (nr_failed) {
        printf("Failed %u %s test%s\n", nr_failed, suite_name, nr_failed > 1 ? "s" : "");
    } else {
        printf("All %s tests OK!\n", suite_name);
    }
    if (netbeans) printf("%%SUITE_FINISHED%% time=%.3f\n", elapsed_from(suite_start_time));
    printf("\n");
}

void start_speed_test_suite(const char *suite, const char *names[], const unsigned int subtests, const unsigned int repeats) {
    unsigned int i;
    start_test_suite(suite);
    nr_subtests = subtests;
    nr_test_repeats = repeats;
    subtest_cpu = malloc(nr_subtests * sizeof (uint64_t *));
    subtest_clock = malloc(nr_subtests * sizeof (clock_t *));
    subtest_names = malloc(nr_subtests * sizeof (char *));
    for (i = 0; i < nr_subtests; ++i) {
        subtest_cpu[i] = calloc(nr_test_repeats, sizeof (uint64_t));
        subtest_clock[i] = calloc(nr_test_repeats, sizeof (clock_t));
        subtest_names[i] = malloc(strlen(names[i]) + 1);
        strncpy(subtest_names[i], names[i], strlen(names[i])+1);
    }
    subtest_cpu_average = calloc(nr_subtests, sizeof (uint64_t));
    subtest_clock_average = calloc(nr_subtests, sizeof (clock_t));
}

void start_speed_subtest_timing(void) {
    subtest_clock_start = clock();
    CPU_CYCLE_COUNT(subtest_cpu_start);
}

void stop_speed_subtest_timing(const unsigned int subtest, const unsigned int repeat_nr) {
    CPU_CYCLE_COUNT(subtest_cpu[subtest][repeat_nr]);
    subtest_clock[subtest][repeat_nr] = clock();
    subtest_cpu[subtest][repeat_nr] -= subtest_cpu_start;
    subtest_cpu_average[subtest] += subtest_cpu[subtest][repeat_nr];
    subtest_clock[subtest][repeat_nr] -= subtest_clock_start;
    subtest_clock_average[subtest] += subtest_clock[subtest][repeat_nr];
}

void end_speed_test_suite(const char* summary) {
    unsigned int i, j;

    uint64_t subtest_cpu_median;
    uint64_t subtest_cpu_var;
    double subtest_cpu_stdev;
    uint64_t cpu_minimum = 0;
    uint64_t cpu_median = 0;
    uint64_t cpu_maximum = 0;
    uint64_t cpu_average = 0;
    uint64_t cpu_var = 0;
    double cpu_stdev = 0;

    uint64_t subtest_clock_median;
    uint64_t subtest_clock_var;
    double subtest_clock_stdev;
    uint64_t clock_minimum = 0;
    uint64_t clock_median = 0;
    uint64_t clock_maximum = 0;
    uint64_t clock_average = 0;
    uint64_t clock_var = 0;
    double clock_stdev = 0;

    print_timings_header();
    print_timings_separator();

    for (i = 0; i < nr_subtests; ++i) {
        qsort(subtest_cpu[i], nr_test_repeats, sizeof (uint64_t), compare_timings);
        subtest_cpu_median = (nr_test_repeats % 2) ? subtest_cpu[i][nr_test_repeats / 2] : (subtest_cpu[i][nr_test_repeats / 2 - 1] + subtest_cpu[i][nr_test_repeats / 2]) / 2;
        subtest_cpu_average[i] /= nr_test_repeats;
        cpu_minimum += subtest_cpu[i][0];
        cpu_maximum += subtest_cpu[i][nr_test_repeats - 1];
        cpu_median += subtest_cpu_median;
        cpu_average += subtest_cpu_average[i];
        subtest_cpu_var = 0;
        for (j = 0; j < nr_test_repeats; ++j) {
            subtest_cpu_var += (subtest_cpu[i][j] - subtest_cpu_average[i]) * (subtest_cpu[i][j] - subtest_cpu_average[i]);
        }
        cpu_var += subtest_cpu_var;
        subtest_cpu_var /= nr_test_repeats;
        subtest_cpu_stdev = sqrt((double) subtest_cpu_var);

        qsort(subtest_clock[i], nr_test_repeats, sizeof (uint64_t), compare_timings);
        subtest_clock_median = (nr_test_repeats % 2) ? subtest_clock[i][nr_test_repeats / 2] : (subtest_clock[i][nr_test_repeats / 2 - 1] + subtest_clock[i][nr_test_repeats / 2]) / 2;
        subtest_clock_average[i] /= nr_test_repeats;
        clock_minimum += subtest_clock[i][0];
        clock_maximum += subtest_clock[i][nr_test_repeats - 1];
        clock_median += subtest_clock_median;
        clock_average += subtest_clock_average[i];
        subtest_clock_var = 0;
        for (j = 0; j < nr_test_repeats; ++j) {
            subtest_clock_var += (subtest_clock[i][j] - subtest_clock_average[i]) * (subtest_clock[i][j] - subtest_clock_average[i]);
        }
        clock_var += subtest_clock_var;
        subtest_clock_var /= nr_test_repeats;
        subtest_clock_stdev = sqrt((double) subtest_clock_var);

        print_cpu_timings(subtest_names[i], subtest_cpu[i][0], subtest_cpu_median, subtest_cpu[i][nr_test_repeats - 1], subtest_cpu_average[i], subtest_cpu_stdev);
        print_clock_timings(subtest_names[i], subtest_clock[i][0], subtest_clock_median, subtest_clock[i][nr_test_repeats - 1], subtest_clock_average[i], subtest_clock_stdev);
    }

    if (summary != NULL) {
        print_timings_separator();
        cpu_var /= nr_test_repeats;
        cpu_stdev = sqrt((double) cpu_var);
        clock_var /= nr_test_repeats;
        clock_stdev = sqrt((double) clock_var);
        print_cpu_timings(summary, cpu_minimum, cpu_median, cpu_maximum, cpu_average, cpu_stdev);
        print_clock_timings(summary, clock_minimum, clock_median, clock_maximum, clock_average, clock_stdev);
    }
    if (netbeans) printf("%%TEST_FINISHED%% time=%.3f %s (%s)\n", elapsed_from(suite_start_time), suite_name, suite_name);
    if (netbeans) printf("%%SUITE_FINISHED%% time=%.3f\n", elapsed_from(suite_start_time));
    printf("\n");
    for (i = 0; i < nr_subtests; ++i) {
        free(subtest_cpu[i]);
        free(subtest_clock[i]);
        free(subtest_names[i]);
    }
    free(subtest_cpu);
    free(subtest_clock);
    free(subtest_names);
    free(subtest_cpu_average);
    free(subtest_clock_average);
}
