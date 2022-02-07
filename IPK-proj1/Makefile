# Makefile
# author: Adam Rajko (xrajko00@stud.fit.vutbr.cz)
# date: 2022-02-06

CC=g++	
CFLAGS=-Wall -Wextra -pedantic

DEPS=error.hpp httplib.hpp
OBJ=error.o httplib.o

all: hinfosvc

hinfosvc: hinfosvc.cpp $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@

%.o : %.c $(DEPS)
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f *.o hinfosvc
