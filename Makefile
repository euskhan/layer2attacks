all: macflooder.o dns.o header.o dnshijacker.o DNSHijacker MACFlooder ARPFlooder ARPspoofing
flood: macflooder.o MACFlooder
arpflooder: arpflooder.o ARPFlooder
dns: dns.o header.o dnshijacker.o DNSHijacker
arpspoofer: ARPspoofing

CXX = gcc -g -Wall
FLAGS = -lnet -lpcap

MACFlooder: macflooder.o
	$(CXX) -o $@ $< $(FLAGS)

ARPFlooder: arpflooder.o
	$(CXX) -o $@ $< $(FLAGS)

DNSHijacker: dns.o header.o dnshijacker.o
	$(CXX) -o DNSHijacker $^ -lpcap

ARPspoofing: ARPspoofing.o
	$(CXX) -o $@ $< $(FLAGS)

%.o: %.c
	$(CXX) -c $< -o $@

clean:
		rm *.o
		rm DNSHijacker
		rm MACFlooder
		rm ARPFlooder
		rm ARPspoofing
