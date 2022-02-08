/**
 * @file httplib.cpp
 * @author Adam Rajko (xrajko00@stud.fit.vutbr.cz)
 * @brief Implementation of analysis for HTTP requests
 * @date 2022-02-06
 *
 */

#include "httplib.hpp"

/**
 * @brief Split function
 *
 * @param str std::string string to split
 * @param del char to be used as delimeter
 * @return std::vector<std::string> vector of stings
 */
std::vector<std::string> split(std::string &str, char del = ' ') {
    if (str.empty()) return {};  // check if empty

    std::vector<std::string> result;
    std::string tmp = "";

    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == del) {
            result.push_back(tmp);
            tmp = "";
        } else {
            tmp += str[i];
        }
    }

    result.push_back(tmp);

    return result;
}

/**
 * @brief Removes spaces before firsrt char
 *
 * @param str std::string string to be aligned
 * @return std::string aligned string
 */
std::string remove_spaces_before_char(std::string &str) {
    std::string result = "";

    int index = 0;
    while (!isalpha(str[index])) index++;
    for (int i = index; str[i] != '\0'; i++) result += str[i];

    return result;
}

/**
 * @brief Get the cpu info object
 *
 * @return std::string CPU name
 */
std::string get_cpu_info() {
    std::ifstream file("/proc/cpuinfo");                                                            // read from file
    std::string input((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));  // convert file content to std::string object
    file.close();

    auto result = split(input, '\n');  // split all new lines
    std::vector<std::string> tmp;

    for (int i = 0; (result[i].compare("\0") != 0); i++) {
        tmp = split(result[i], ':');
        if (tmp[0].find((std::string) "model name") == 0)
            return remove_spaces_before_char(tmp[1]);
    }

    return {};
}

/**
 * @brief Get the hostname string object
 *
 * @return std::string Hostname
 */
std::string get_hostname() {
    // get hostname from file
    std::ifstream file("/proc/sys/kernel/hostname");
    std::string result;
    std::getline(file, result);
    file.close();

    return result;
}

/**
 * @brief Get the cpu times object
 *
 * @return std::vector<size_t> [0] -> idle time, [1] -> total time
 */
std::vector<size_t> get_cpu_times() {
    std::ifstream file("/proc/stat");

    file.ignore(5, ' ');            // skip cpu prefix (ignore for space)
    std::vector<size_t> cpu_times;  // vector for all cpu times
    std::vector<size_t> result;     // return value
    size_t total_time = 0;

    // push all apu times to vector
    for (size_t time; file >> time; cpu_times.push_back(time))
        ;

    file.close();

    result.push_back(cpu_times[3] + cpu_times[4]);  // idle_time + io_wait

    // sum all cpu times (total time)
    for (int i = 0; i < cpu_times.size(); i++) total_time += cpu_times[i];

    result.push_back(total_time);

    return result;
}

/**
 * @brief Get cpu load in percentage
 *
 * @return std::string load in percentage
 */
std::string cpu_load() {
    auto tmp = get_cpu_times();

    // 100 * (total_time - idle_time) / total_time
    float percentage = 100 * ((float)tmp[1] - (float)tmp[0]) / (float)tmp[1];

    return std::to_string((int)std::round(percentage)) + "%";
}

/**
 * @brief Converts messege for HTTP transmission
 *
 * @param text std::string message to be sent
 * @return std::string HTTP response
 */
std::string http_response(std::string text) {
    std::string result = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ";
    result += std::to_string(text.size()) + "\r\n\r\n" + text;

    return result;
}

/**
 * @brief Analyse HTTP request
 *
 * @param recv std::string received message
 * @return std::string respose
 */
std::string http_analyse(std::string recv) {
    auto str = split(recv);  // split received message

    // check if used method is GET
    if (str[0].compare((std::string) "GET") == 0) {
        if (str[1].compare((std::string) "/hostname") == 0) {
            return http_response(get_hostname());
        } else if (str[1].compare((std::string) "/cpu-name") == 0) {
            return http_response(get_cpu_info());
        } else if (str[1].compare((std::string) "/load") == 0) {
            return http_response(cpu_load());
        }
    }

    return "HTTP/1.1 400 Bad Request\r\n\r\n";
}
