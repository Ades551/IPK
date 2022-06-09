# IPK - packet sniffer
Program for monitoring network traffic within the computer.

## Compile and run
```console
$ make
$ sudo ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} {-n num}
```

## Example how to run packet sniffer
```console
$ sudo ./ipk-sniffer -i
$ sudo ./ipk-sniffer -i enp3s0
$ sudo ./ipk-sniffer -i wlp2s0 --arp --icmp -n 50
$ sudo ./ipk-sniffer -i enp3s0 -t -u -p 23
```

## Return values
- 0 --> OK
- 1 --> wrong argument
- 2 --> PCAP error

## Archive content
- error.hpp
- error.cpp
- ipk-sniffer.cpp
- Makefile
- README.md
- manual.pdf
