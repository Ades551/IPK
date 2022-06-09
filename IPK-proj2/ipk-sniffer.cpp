/**
 * @file sniffer.cpp
 * @author Adam Rajko <xrajko00@stud.fit.vutbr.cz>
 * @brief Implementation of packet sniffer
 * @date 2022-04-20
 *
 */

#include <arpa/inet.h>      // inet_ntop
#include <getopt.h>         // struct option, getopt_long
#include <netinet/ether.h>  // struct ether_header
#include <netinet/in.h>     // ntohs
#include <netinet/ip.h>     // struct ip
#include <netinet/ip6.h>    // struct ip6_hdr
#include <netinet/tcp.h>    // struct tcphdr
#include <netinet/udp.h>    // struct udphdr
#include <pcap.h>
#include <time.h>  // localtime, strftime

#include <cmath>     // round
#include <iomanip>   // setfill, setw
#include <iostream>  // cout
#include <sstream>   // stringstream
#include <string>    // string

#include "error.hpp"  // error_msg

#define ALL_PORTS -1

#define PACKET_HEADER(_struct_type, _ip_protocol)                                                                       \
    struct _struct_type *header = (_struct_type *)(packet + sizeof(struct ether_header) + sizeof(struct _ip_protocol)); \
    out << "src port:\t" << std::to_string(ntohs(header->source)) << '\n';                                              \
    out << "dst port:\t" << std::to_string(ntohs(header->dest)) << '\n'

std::string handle_ether_ip(const struct pcap_pkthdr *pkthdr, const u_char *packet);
std::string handle_ether_arp(const struct pcap_pkthdr *pkthdr, const u_char *packet);
std::string handle_ether_ipv6(const struct pcap_pkthdr *pkthdr, const u_char *packet);
std::string ether_ntoa_zero_fill(ether_addr *addr);
std::string filter_expression_init(int tcp, int udp, int icmp, int arp, int port);
std::string get_data(u_char *data, u_int32_t data_length);

bool valid_interface(std::string value);

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void print_interfaces();

int main(int argc, char **argv) {
    // initialize parameters to default values
    int tcp = 0, udp = 0, icmp = 0, arp = 0, n = 1, port = ALL_PORTS;

    /**
     * Option parsing
     * @see https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
     */

    // long options
    struct option long_options[] = {
        {"interface", optional_argument, NULL, 'i'},
        {"tcp", no_argument, &tcp, 1},
        {"udp", no_argument, &udp, 1},
        {"icmp", no_argument, &icmp, 1},
        {"arp", no_argument, &arp, 1},
        {0, 0, 0, 0}};

    // short options
    // ::    - optional argument
    // :     - required argument
    const char *short_options = "i::p:tun:";

    std::string filter_exp;  // filter expression
    std::string device;      // device to sniff on

    int c = -1;
    while ((c = getopt_long(argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (c) {
            case 0:
                break;
            case 'i':
                /**
                 * optional short argument
                 * @see https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
                 */
                if (!optarg && optind < argc && NULL != argv[optind] && '\0' != argv[optind][0] && '-' != argv[optind][0]) {
                    device = argv[optind++];
                } else {
                    print_interfaces();
                }
                break;

            case 'p':
                port = atoi(optarg);
                /**
                 * port range
                 * @see: https://www.sciencedirect.com/topics/computer-science/registered-port
                 */
                if (port < 0 || port > 65535) error_msg(10, "Invalid port number!");
                break;

            case 't':
                tcp = 1;
                break;

            case 'u':
                udp = 1;
                break;

            case 'n':
                if ((n = atoi(optarg)) < 0) error_msg(10, "Invalid number!");
                break;

            default:
                return 1;
                break;
        }
    }

    /**
     * Initialization of packet sniffing
     * @see https://www.tcpdump.org/pcap.html
     */
    pcap_t *handle;                 // Session handle
    char errbuf[PCAP_ERRBUF_SIZE];  // Error string
    struct bpf_program fp;          // The compiled filter
    bpf_u_int32 mask;               // Our netmask
    bpf_u_int32 net;                // Our IP

    // no arguments
    if (argc == 1) return 0;

    // invalid use of device
    if (!valid_interface(device))
        error_msg(2, "Device: %s is not supported!", device.c_str());

    // set filter
    if ((filter_exp = filter_expression_init(tcp, udp, icmp, arp, port)).empty())
        filter_exp = "tcp or udp or arp or icmp or icmp6";

    // find the properties for the device
    if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1)
        error_msg(2, "Couldn't get netmask for device %s: %s", device.c_str(), errbuf);

    // open the session in promiscuous mode
    if ((handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf)) == NULL)
        error_msg(2, "Couldn't open device %s: %s\n", device.c_str(), errbuf);

    /**
     * @see https://linux.die.net/man/7/pcap-linktype
     */

    // check if session can handle ethernet headers
    if (pcap_datalink(handle) != DLT_EN10MB)
        error_msg(2, "Device %s doesn't provide Ethernet headers - not supported", device.c_str());

    // compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1)
        error_msg(2, "Couldn't parse filter %s: %s", filter_exp, pcap_geterr(handle));

    if (pcap_setfilter(handle, &fp) == -1)
        error_msg(2, "Couldn't install filter %s: %s", filter_exp, pcap_geterr(handle));

    /**
     * @see https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
     */
    pcap_loop(handle, n, packet_handler, NULL);

    return 0;
}

/**
 * @brief Handle IP protocol
 *
 * @param pkthdr packet basic info (time, size)
 * @param packet packet data
 */
std::string handle_ether_ip(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    std::stringstream out;
    out << "src IP:\t\t" << std::string(source_ip) << '\n';
    out << "dst IP:\t\t" << std::string(dest_ip) << '\n';

    switch (ip_header->ip_p) {
        case IPPROTO_TCP: {
            PACKET_HEADER(tcphdr, ip);
        } break;
        case IPPROTO_UDP: {
            PACKET_HEADER(udphdr, ip);
        } break;
        case IPPROTO_ICMP:
            break;
        default:
            return {};
    }

    out << '\n';
    out << get_data((u_char *)packet, pkthdr->caplen) << '\n';

    return out.str();
}

/**
 * @brief Handle ARP
 *
 * @param pkthdr packet basic info (time, size)
 * @param packet packet data
 */
std::string handle_ether_arp(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    std::stringstream out;

    out << '\n';
    out << get_data((u_char *)packet, pkthdr->caplen);

    return out.str();
}

/**
 * @brief Handle IPv6 protocol
 *
 * @param pkthdr packet basic info (time, size)
 * @param packet packet data
 */
std::string handle_ether_ipv6(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    char source_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ip6_header->ip6_src), source_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dest_ip, INET6_ADDRSTRLEN);

    std::stringstream out;
    out << "src IP:\t\t" << std::string(source_ip) << '\n';
    out << "dst IP:\t\t" << std::string(dest_ip) << '\n';

    switch (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        case IPPROTO_TCP: {
            PACKET_HEADER(tcphdr, ip6_hdr);
        } break;
        case IPPROTO_UDP: {
            PACKET_HEADER(udphdr, ip6_hdr);
        } break;
        case IPPROTO_ICMPV6:
            break;
        default:
            return {};
    }

    out << '\n';
    out << get_data((u_char *)packet, pkthdr->caplen);

    return out.str();
}

/**
 * @brief Callback function for packet handling
 *
 * @param user_data data passed by pcap_loop
 * @param pkthdr packet basic info (time, size)
 * @param packet packet data
 */
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user_data;
    struct ether_header *ethernet_header = (struct ether_header *)packet;  // ethernet header

    /**
     * @see https://www.cplusplus.com/reference/ctime/strftime/
     */

    /********* time conversion ************/
    char timebuffer[50];
    char timebuffer_2[50];

    struct tm *timeinfo = localtime(&pkthdr->ts.tv_sec);

    int milisec = std::round(pkthdr->ts.tv_usec / 1000);
    char sign = timeinfo->tm_gmtoff < 0 ? '-' : '+';
    int timezone = (int)timeinfo->tm_gmtoff / 3600;

    strftime(timebuffer, sizeof(timebuffer), "%Y-%m-%dT%H:%M:%S", timeinfo);
    sprintf(timebuffer_2, ".%03d%c%02d:00", milisec, sign, timezone);
    /********* time conversion ************/

    std::stringstream out;
    out << "timestamp:\t" << timebuffer << timebuffer_2 << '\n';
    out << "src MAC:\t" << ether_ntoa_zero_fill((ether_addr *)ethernet_header->ether_shost) << '\n';
    out << "dst MAC:\t" << ether_ntoa_zero_fill((ether_addr *)ethernet_header->ether_dhost) << '\n';
    out << "frame length:\t" << pkthdr->len << " bytes" << '\n';

    switch (ntohs(ethernet_header->ether_type)) {
        case ETHERTYPE_IP:
            out << handle_ether_ip(pkthdr, packet);
            break;
        case ETHERTYPE_ARP:
            out << handle_ether_arp(pkthdr, packet);
            break;
        case ETHERTYPE_IPV6:
            out << handle_ether_ipv6(pkthdr, packet);
            break;
        default:
            return;
    }

    std::cout << out.str() << std::endl;
}

/**
 * @brief Get the data from packet
 *
 * @param data packet data
 * @param data_length length of data
 * @return std::string formated packet data
 */
std::string get_data(u_char *data, unsigned data_length) {
    std::stringstream out;
    out << "0x0000: ";

    bool align = false;

    for (unsigned i = 1; i <= data_length; i++) {
        // check if data should be aligned
        align = (i == data_length && data_length % 16 != 0);

        out << std::setfill('0') << std::setw(2) << std::hex << (u_int)data[i - 1] << " ";

        // split every octet
        if ((i % 8 == 0) && (i % 16 != 0))
            out << ' ';

        // new line
        if ((i % 16 == 0) || align) {
            int x = 16;

            if (align)
                x = (data_length % 16);

            out << std::setfill(' ') << std::setw(((16 - x) * 3) + 1) << '\t';

            for (unsigned int j = i - x; j < i; j++) {
                if (j % 8 == 0) out << "  ";

                // print only readable chars
                if ((data[j] >= 32 && data[j] <= 126)) {
                    out << (char)data[j];
                } else {
                    out << ".";
                }
            }

            out << "\n";

            // check if last line
            if (i != data_length)
                out << "0x" << std::setfill('0') << std::setw(4) << std::hex << i << ": ";
        }
    }

    return out.str();
}

/**
 * @brief Creates filter expression
 *
 * @param tcp tcp option value
 * @param udp udp option value
 * @param icmp icmp option value
 * @param arp arp option value
 * @param port port option value
 * @return std::string filter expression
 */
std::string filter_expression_init(int tcp, int udp, int icmp, int arp, int port) {
    std::stringstream out;

    if (port != ALL_PORTS) {  // for specific port
        tcp ? out << "tcp port " << port : out;
        udp ? (out.str().size() ? out << " or udp port " << port : out << "udp port " << port) : out;
    } else {  // for all ports
        tcp ? out << "tcp" : out;
        udp ? (out.str().size() ? out << " or udp" : out << "udp") : out;
    }

    arp ? (out.str().size() ? out << " or arp" : out << "arp") : out;
    icmp ? (out.str().size() ? out << " or icmp or icmp6" : out << "icmp or icmp6") : out;

    return out.str();
}

/**
 * @brief Prints every available interface to stdout
 *
 */
void print_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;

    // find every available device
    if (pcap_findalldevs(&interfaces, errbuf) < 0) {
        error_msg(2, "Couldn't find default device: %s\n", errbuf);
    }

    // list every interface and print them to stdout
    for (pcap_if_t *interface = interfaces; interface != NULL; interface = interface->next)
        std::cout << interface->name << std::endl;

    // free every device
    pcap_freealldevs(interfaces);

    exit(0);
}

/**
 * @brief Checks if interface is valid
 *
 * @param value std::string interface
 * @return true if interface is valid else false
 */
bool valid_interface(std::string value) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;

    // find every available device
    if (pcap_findalldevs(&interfaces, errbuf) < 0) {
        error_msg(2, "Couldn't find default device: %s\n", errbuf);
    }

    // list every interface and check if valid
    for (pcap_if_t *interface = interfaces; interface != NULL; interface = interface->next)
        if (std::string(interface->name).compare(value) == 0) return true;

    // free every device
    pcap_freealldevs(interfaces);

    return false;
}

/**
 * @brief MAC addres to hex with zero fill
 *
 * @param addr addres
 * @return std::string mac address
 */
std::string ether_ntoa_zero_fill(ether_addr *addr) {
    std::stringstream out;

    for (int i = 0; i < 6; i++) {
        out << std::setfill('0') << std::setw(2) << std::hex << (u_int)addr->ether_addr_octet[i];
        if (i != 5) out << ":";
    }

    return out.str();
}
