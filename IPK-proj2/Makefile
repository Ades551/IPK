# Makefile
# author: Adam Rajko (xrajko00@stud.fit.vutbr.cz)
# date: 2022-04-20

CC=g++
CFLAGS=-Wall -Wextra -pedantic
LIB=-lpcap

DEPS=error.hpp
OBJ=error.o

all: ipk-sniffer

ipk-sniffer: ipk-sniffer.cpp $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LIB)

%.o : %.cpp $(DEPS)
	$(CC) $(CFLAGS) -c $<

.PHONY: pack
pack: clean
	tar -cvf xrajko00.tar *.hpp *.cpp Makefile README.md manual.pdf

.PHONY: clean
clean:
	rm -f *.o ipk-sniffer xrajko00.tar
