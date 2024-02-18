This packet sniffer captures packets and extract the headers.
It also identifies the various protocols ICMP, TCP, UDP.

The main purpose of this project is to implement the understandings of computer networks. It uses "libcap" library to capture packets.

Requirements:

libcap library:

sudo apt-get install libpcap-dev


compile the program:

g++ sniffer.c -o sniffer -lpcap

To run:
sudo ./sniffer