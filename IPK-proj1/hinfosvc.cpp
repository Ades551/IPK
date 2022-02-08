/**
 * @file hinfosvc.cpp
 * @author Adam Rajko (xrajko00@stud.fit.vutbr.cz)
 * @brief Implementation of socket server for HTTP requests
 * @date 2022-02-06
 *
 */

#include <arpa/inet.h>   // inet_ntoa
#include <ctype.h>       // isdigit
#include <netinet/in.h>  // htons
#include <sys/socket.h>  // socket, setsockopt, bind, listen
#include <unistd.h>      // read, close

#include <string>

#include "error.hpp"
#include "httplib.hpp"

bool str_is_number(std::string &str);

int main(int argc, char **argv) {
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
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)) < 0) error_msg(1, "Setting socket options!");

    // bind server
    if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) error_msg(1, "For server to bind!");

    // losten to port
    if (listen(server_fd, 1) < 0) error_msg(1, "Listening to incomming connections!");

    while (true) {
        // accept incomming connections
        new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);

        // check if connection was accepted
        if (new_socket < 0) error_msg(1, "Socket accept failed!");

        // read socket message
        if (read(new_socket, buffer, 255) < 0) error_msg(1, "Socket read failed!");

        std::string response = http_analyse(std::string(buffer));
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
