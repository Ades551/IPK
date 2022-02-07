/**
 * @file hinfosvc.cpp
 * @author Adam Rajko (xrajko00@stud.fit.vutbr.cz)
 * @brief Implementation of socket server for HTTP requests
 * @date 2022-02-06
 *
 */

#include <arpa/inet.h>  // inet_ntoa
#include <ctype.h>      // isdigit
#include <netinet/in.h>
//#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "error.hpp"
#include "httplib.hpp"

bool str_is_number(std::string &str);
void signal_handler(int signal_num);

int main(int argc, char **argv) {
    // signal(SIGINT, signal_handler);

    if (argc != 2) {
        error_msg(1, "Invalid number of arguments!");
    }

    std::string port_str = argv[1];

    if (!str_is_number(port_str)) {
        error_msg(1, "Invalid argument type!");
    }

    int server_fd, new_socket;
    struct sockaddr_in serv_addr, client_addr;
    socklen_t addrlen = sizeof(client_addr);
    char buffer[256] = {
        0,
    };
    int option = 1;

    int port = std::stoi(port_str);  // convert port to int

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    // create socket
    // protocol family, protocol type, protocol (0) -> default
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) error_msg(1, "Socket creation!");

    // set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)) < 0) error_msg(1, "Socket options!");

    // bind server
    if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) error_msg(1, "Server bind!");

    // losten to port
    if (listen(server_fd, 1) < 0) error_msg(1, "Listen to incomming connections!");

    while (true) {
        new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);

        if (new_socket < 0) {
            error_msg(1, "Accept failed!");
        } else {
            printf("server: got connection from %s port %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        }

        if (read(new_socket, buffer, 255) < 0) error_msg(1, "Read!");

        std::string response = http_analyse(std::string(buffer, 255));
        if (response.empty()) error_msg(1, "Response failed!");

        // printf("client request:\n%s\n", buffer);
        // const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello world!";

        send(new_socket, response.c_str(), response.size(), 0);

        close(new_socket);
    }

    close(server_fd);

    return 0;
}

bool str_is_number(std::string &str) {
    for (unsigned i = 0; i < str.length(); i++)
        if (!isdigit(str[i])) return false;

    return true;
}

// void signal_handler(int signal_num) {
//     exit(signal_num);
// }
