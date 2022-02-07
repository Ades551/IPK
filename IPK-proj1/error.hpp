/**
 * @file error.hpp
 * @author Adam Rajko (xrajko00@stud.fit.vutbr.cz)
 * @brief Header file for analysing HTTP requests
 * @date 2022-02-06
 *
 */

#ifndef __ERROR_H
#define __ERROR_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void error_msg(int error_num, const char *fmt, ...);

#endif  // __ERROR_H
