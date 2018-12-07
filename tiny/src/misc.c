/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 * Hayo Baan
 *
 * All rights reserved. A copyright license for redistribution and use in
 * source and binary forms, with or without modification, is hereby granted for
 * non-commercial, experimental, research, public review and evaluation
 * purposes, provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * Implementation of the miscellaneous functions.
 */

#include "misc.h"

#include <stdio.h>

void print_hex(const char *var, const unsigned char *data, const size_t nr_elements, const size_t element_size) {
    size_t i, ii;
    if (var != NULL) {
        printf("%s[%zu]=", var, nr_elements);
    }
    for (i = 0; i < nr_elements; ++i) {
        if (i > 0) {
            printf(" ");
        }
        for (ii = element_size; ii > 0; --ii) {
            printf("%02hhX", data[i * element_size + ii - 1]);
        }
    }
    if (var != NULL) {
        printf("\n");
    }
}

void print_sage_u_vector(const char *var, const uint16_t *vector, const size_t nr_elements) {
    size_t i;
    if (var != NULL) {
        printf("%s[%zu]=", var, nr_elements);
    }
    printf("[ ");
    for (i = 0; i < nr_elements; ++i) {
        if (i > 0) {
            printf(", ");
        }
        printf("%hu", vector[i]);
    }
    printf(" ]");
    if (var != NULL) {
        printf("\n");
    }
}

void print_sage_u_matrix(const char *var, const uint16_t *matrix, const size_t nr_rows, const size_t nr_columns) {
    size_t i;
    if (var != NULL) {
        printf("%s[%zu][%zu]=", var, nr_rows, nr_columns);
    }
    printf("Matrix([");
    for (i = 0; i < nr_rows; ++i) {
        if (i > 0) {
            printf(",");
        }
        if (nr_rows > 1) {
            printf("\n");
        } else {
            printf(" ");
        }
        print_sage_u_vector(NULL, matrix + i*nr_columns, nr_columns);
    }
    if (nr_rows > 1) {
        printf("\n])");
    } else {
        printf(" ])");
    }
    if (var != NULL) {
        printf("\n");
    }
}

void print_sage_u_vector_matrix(const char *var, const uint16_t *matrix, const size_t nr_rows, const size_t nr_columns, const size_t nr_elements) {
    size_t i, j;
    if (nr_elements == 1) {
        print_sage_u_matrix(var, matrix, nr_rows, nr_columns);
    } else if (nr_rows == 1 && nr_columns == 1) {
        print_sage_u_vector(var, matrix, nr_elements);
    } else {
        if (var != NULL) {
            printf("%s[%zu][%zu][%zu]=", var, nr_rows, nr_columns, nr_elements);
        }
        printf("Matrix([");
        for (i = 0; i < nr_rows; ++i) {
            if (i > 0) {
                printf(",");
            }
            if (nr_rows > 1) {
                printf("\n[");
            } else {
                printf(" [");
            }
            for (j = 0; j < nr_columns; ++j) {
                if (j > 0) {
                    printf(",");
                }
                if (nr_columns > 1 && nr_elements > 1) {
                    printf("\n  ");
                } else {
                    printf(" ");
                }
                print_sage_u_vector(NULL, matrix + (i * nr_columns + j) * nr_elements, nr_elements);
            }
            if (nr_columns > 1 && nr_elements > 1) {
                printf("\n]");
            } else {
                printf(" ]");
            }
        }
        if (nr_rows > 1) {
            printf("\n])");
        } else {
            printf(" ])");
        }
        if (var != NULL) {
            printf("\n");
        }
    }
}

void print_sage_s_vector(const char *var, const int16_t *poly, const size_t nr_elements) {
    size_t i;
    if (var != NULL) {
        printf("%s[%zu]=", var, nr_elements);
    }
    printf("[ ");
    for (i = 0; i < nr_elements; ++i) {
        if (i > 0) {
            printf(", ");
        }
        printf("%hd", poly[i]);
    }
    printf(" ]");
    if (var != NULL) {
        printf("\n");
    }
}

void print_sage_s_matrix(const char *var, const int16_t *matrix, const size_t nr_rows, const size_t nr_columns) {
    size_t i;
    if (var != NULL) {
        printf("%s[%zu][%zu]=", var, nr_rows, nr_columns);
    }
    printf("Matrix([");
    for (i = 0; i < nr_rows; ++i) {
        if (i > 0) {
            printf(",");
        }
        if (nr_rows > 1) {
            printf("\n");
        } else {
            printf(" ");
        }
        print_sage_s_vector(NULL, matrix + i*nr_columns, nr_columns);
    }
    if (nr_rows > 1) {
        printf("\n])");
    } else {
        printf(" ])");
    }
    if (var != NULL) {
        printf("\n");
    }
}

void print_sage_s_vector_matrix(const char *var, const int16_t *matrix, const size_t nr_rows, const size_t nr_columns, const size_t nr_elements) {
    size_t i, j;
    if (nr_elements == 1) {
        print_sage_s_matrix(var, matrix, nr_rows, nr_columns);
    } else if (nr_rows == 1 && nr_columns == 1) {
        print_sage_s_vector(var, matrix, nr_elements);
    } else {
        if (var != NULL) {
            printf("%s[%zu][%zu][%zu]=", var, nr_rows, nr_columns, nr_elements);
        }
        printf("Matrix([");
        for (i = 0; i < nr_rows; ++i) {
            if (i > 0) {
                printf(",");
            }
            if (nr_rows > 1) {
                printf("\n[");
            } else {
                printf(" [");
            }
            for (j = 0; j < nr_columns; ++j) {
                if (j > 0) {
                    printf(",");
                }
                if (nr_columns > 1 && nr_elements > 1) {
                    printf("\n  ");
                } else {
                    printf(" ");
                }
                print_sage_s_vector(NULL, matrix + (i * nr_columns + j) * nr_elements, nr_elements);
            }
            if (nr_columns > 1 && nr_elements > 1) {
                printf("\n]");
            } else {
                printf(" ]");
            }
        }
        if (nr_rows > 1) {
            printf("\n])");
        } else {
            printf(" ])");
        }
        if (var != NULL) {
            printf("\n");
        }
    }
}

uint32_t ceil_log2(uint32_t x) {
    uint32_t bits = 0;
    uint32_t ones = 0;

    while (x >>= 1) {
        ones += x & 0x1;
        ++bits;
    }
    if (ones > 1) { /* ceil */
        ++bits;
    }

    return bits;
}
