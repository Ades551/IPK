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

%.o : %.cpp $(DEPS)
	$(CC) $(CFLAGS) -c $<

.PHONY: pack
pack: clean
	zip xrajko00.zip *.hpp *.cpp Makefile README.md

.PHONY: clean
clean:
	rm -f *.o hinfosvc xrajko00.zip
