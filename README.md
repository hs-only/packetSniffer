# Packet Sniffer
## About
This packet sniffer captures packets from data link layers and extract the headers.
It also identifies the various protocols ICMP, TCP, UDP.

The main purpose of this project is to implement the understandings of computer networks. It uses "libcap" library to capture packets.

## Requirements:
#### sudo privilege
#### libcap library:

sudo apt-get install libpcap-dev


## compile the program:

g++ sniffer.c -o sniffer -lpcap

## To run:
sudo ./sniffer

![image1](https://github.com/hs-only/packetSniffer/blob/main/images/1.png?raw=true)
![image2](https://github.com/hs-only/packetSniffer/blob/main/images/2.png?raw=true)
![image3](https://github.com/hs-only/packetSniffer/blob/main/images/3.png?raw=true)
![image4](https://github.com/hs-only/packetSniffer/blob/main/images/4.png?raw=true)


