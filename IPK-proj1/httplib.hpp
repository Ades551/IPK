/**
 * @file httplib.hpp
 * @author Adam Rajko (xrajko00@stud.fit.vutbr.cz)
 * @brief Header file for analysing HTTP requests
 * @date 2022-02-06
 *
 */

#ifndef __HTTP_LIB_H
#define __HTTP_LIB_H

#include <unistd.h>

#include <fstream>
#include <string>
#include <vector>

std::string http_analyse(std::string recv);

#endif  // __HTTP_LIB_H
