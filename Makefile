#gcc -Wall -g -o2 -pthread jenkins_hash.c memcached.c -levent -o memcached-server
# Makefile for Writing Make Files Example

# *****************************************************
# Variables to control Makefile operation

CXX = gcc
CXXFLAGS = -Wall -g -o2 -pthread
LDFLAGS=-levent

# ****************************************************
# Targets needed to bring the executable up to date

memcached-server: jenkins_hash.o memcached.o
	$(CXX) $(CXXFLAGS)  -o memcached-server jenkins_hash.o memcached.o $(LDFLAGS)

# The main.o target can be written more simply

memcached.o: memcached.c protocol_binary.h

jenkins_hash.o: jenkins_hash.c jenkins_hash.h

clean: 
	rm -f *.o memcached-server
