/**
 * @file error.hpp
 * @author Adam Rajko (xrajko00@stud.fit.vutbr.cz)
 * @brief Header file for analysing HTTP requests
 * @date 2022-02-06
 *
 */

#include "error.hpp"

void error_msg(int error_num, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    fprintf(stderr, "%s%s%s", "\x1B[31m", "Error: ", "\x1B[0m");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");

    va_end(ap);

    exit(error_num);
}
