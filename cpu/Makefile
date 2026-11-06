CXX ?= g++
CXXFLAGS ?= -O3 -std=c++17 -Wall

all: leap_demo pcap2keys
leap_demo: leap_demo.cpp leap.h
	$(CXX) $(CXXFLAGS) -o $@ leap_demo.cpp
pcap2keys: pcap2keys.cpp
	$(CXX) $(CXXFLAGS) -o $@ pcap2keys.cpp
clean:
	rm -f leap_demo pcap2keys
