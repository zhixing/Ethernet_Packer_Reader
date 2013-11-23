@Author: Yang Zhixing

- How to compile:
	- Go to the src folder:
	- javac PacketParser.java
	- javac DNSParser.java

- How to run:
	- java PacketParser hex.dat > PacketParser.out
	- java DNSParser hex.dat > DNSParser.out

- Extra Features:
	- In question 1, able to analyze ping request and ping reply packets, and print their number.
	- In question 2, able to analyze and print out responses of other queries including 'A' queries.
	- In question 2, albe to analyze and print out details of RRs of other types, including:
		- A Records
		- NS Records
		- CNAME Records
		- SOA Records
		- PTR Records

- Sample Output Files:
	- Q1: PacketParser.out
	- Q2: DNSParser.out

- Counting logic in question A:
	- Ethernet Frame offset: 14 bytes.
	- Depending on the EtherType, the packets can be categorized as follows:
		- ARP
		- IP4
			- ICMP
			- TCP
				- DNS
			- UDP
				- DNS
	- Didn't count IPv6

- Counting logic in question B:
	- Assume each packet only has one question, multiple RRs.
	- Didn't count DNS in TCP
	- The MDNS packets are ignored.

- Development Platform:
	- Max OS X 10.9
	- java version "1.7.0_40"
	- Java(TM) SE Runtime Environment (build 1.7.0_40-b43)
	- Java HotSpot(TM) 64-Bit Server VM (build 24.0-b56, mixed mode)