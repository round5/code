/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of miscellaneous macros and functions.
 */

#ifndef MISC_H
#define MISC_H

#include <stdlib.h>
#include <stdint.h>

/** Macro for printing errors. */
#ifdef DEBUG
#include <stdio.h>
#define DEBUG_ERROR(...) fprintf(stderr, __VA_ARGS__)
#define DEBUG_PRINT(code) code
#else
#define DEBUG_ERROR(...) do {} while (0)
#define DEBUG_PRINT(code)
#endif

// operations
#define ROUND(x) ((int)(x + 0.5))
#define CEIL_DIV(a,b) ((a+b-1)/b)
#define BITS_TO_BYTES(b) (CEIL_DIV(b,8))

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Prints the given data as hex digits.
     *
     * @param[in] var          the name of the data variable, printed before the data followed by an `=`,
     *                         can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] data         the data to print
     * @param[in] nr_elements  the number of elements in the data
     * @param[in] element_size the size of the elements in bytes (bytes will be reversed inside element)
     */
    void print_hex(const char *var, const unsigned char *data, const size_t nr_elements, const size_t element_size);

    /**
     * Prints the given vector in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the vector content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] vector      the vector
     * @param[in] nr_elements the number of elements of the vector
     */
    void print_sage_u_vector(const char *var, const uint16_t *vector, const size_t nr_elements);

    /**
     * Prints the given scalar matrix in a format usable within sage.
     *
     * @param[in] var        the name of the variable, printed before the matrix content followed by an `=`,
     *                       can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix     the matrix
     * @param[in] nr_rows    the number of rows
     * @param[in] nr_columns the number of columns
     */
    void print_sage_u_matrix(const char *var, const uint16_t *matrix, const size_t nr_rows, const size_t nr_columns);

    /**
     * Prints the given matrix of vectors in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the matrix content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix      the matrix
     * @param[in] nr_rows     the number of rows
     * @param[in] nr_columns  the number of columns
     * @param[in] nr_elements the number of elements of the vectors
     */
    void print_sage_u_vector_matrix(const char *var, const uint16_t *matrix, const size_t nr_rows, const size_t nr_columns, const size_t nr_elements);

    /**
     * Prints the given vector in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the vector content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] vector      the vector
     * @param[in] nr_elements the number of elements of the vector
     */
    void print_sage_s_vector(const char *var, const int16_t *vector, const size_t nr_elements);

    /**
     * Prints the given scalar matrix in a format usable within sage.
     *
     * @param[in] var        the name of the variable, printed before the matrix content followed by an `=`,
     *                       can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix     the matrix
     * @param[in] nr_rows    the number of rows
     * @param[in] nr_columns the number of columns
     */
    void print_sage_s_matrix(const char *var, const int16_t *matrix, const size_t nr_rows, const size_t nr_columns);

    /**
     * Prints the given matrix of vectors in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the matrix content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix      the matrix
     * @param[in] nr_rows     the number of rows
     * @param[in] nr_columns  the number of columns
     * @param[in] nr_elements the number of elements of the vectors
     */
    void print_sage_s_vector_matrix(const char *var, const int16_t *matrix, const size_t nr_rows, const size_t nr_columns, const size_t nr_elements);

    /**
     * Computes the log2 of a number, rounding up if it's not exact.
     *
     * @param[in] x  the value to compute the log2 for
     * @return ceil(log2(x))
     */
    uint32_t ceil_log2(uint32_t x);

#ifdef __cplusplus
}
#endif

#endif /* MISC_H */
