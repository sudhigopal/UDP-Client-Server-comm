# Project 1
## PCAP File parsing with server client communication

### Objective

	In this project we parse a binary file containing Ethernet frames that follow the IEEE 802.3 
	standard packets. By performaing the parsing we will know how the frames and packets are injected 
	into the network, on top of parsing we have a client and server programs that communicates using
	UDP sockets to sent the ethernet frames generated.


### Project description

	The layout shown below is an IP datagram header, which basically consists of all the required 
	attributes of a packet for communication between server and a client.

	0 					1 					2 					3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|Version| IHL |Type of Service| 		Total Length 			|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| 		Identification 		  |Flags|      Fragment Offset  	|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| Time to Live | 	Protocol  | 	Header Checksum				|	
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| 						Source Address 							|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| 						Destination Address 					|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| 				Options 						| 	Padding	 	|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	1.	Our code first has to read the PCAP file and select a packet carrying TCP protocol with IPv4 
	address, this is done at the client side of the code (client.c).
	
	2.	Then the binary data is sent to the server side, where it processes the data prints it in the 
	specified format (server.c and pcap_server.h).
	
	3.	To process the data, I have made use of couple of structures which defines IP header and Ethernet
	header as shown below.

	#define Size_Ethernet 14
	#define Ether_Addr_Len 6
	#define	ether_IP 0x0800


	struct sniffEther
	{
		const struct ether_addr ether_dhost[Ether_Addr_Len];
		const struct ether_addr ether_shost[Ether_Addr_Len];
		u_short ether_type;
	};

	//IP structure

	struct sniffIp
	{
		u_char ip_vhl; /* version << 4 and header len >> 5*/
		u_char ip_tos;  /*tos --> type of service*/
		u_short ip_len;	//Total length
		u_short ip_id;	//Identification
		#define ip_rf 0x8000	//reserved fragment flag
		#define ip_df 0x4000	//dont fragment flag
		#define ip_mf 0x2000	//more fragment flag
		#define ip_offmask 0x1fff //mask for fragment flag
		u_short ip_reserved_zero; //Check for flag
		u_short ip_off;	//offset
		u_char ip_ttl;	//time to live
		u_char ip_p;	//protocol
		u_short ip_sum;	//checksum
		struct in_addr ip_src, ip_dst; //source and destination address
	};

	#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

	4.	The communication here is one-way. Client sends the read data to server and server prints 
		it in the console

	5.	To run the code, first run the server code followed by client code in different terminal.

	6.	It takes < 1sec to process the whole data.

### Output

	Ether:	-----Ether Header-----
	Ether:
	Ether:	Packet Size : 305 bytes
	Ether:	Destination : 45:0:0:28:25:de
	Ether:	Source 	    : 83:6f:0:0:6f:6f
	Ether:	EtherType  : 800 (IP)
	Ether:

	IP:	-----IP Header-----
	IP:
	IP:	Version = 4
	IP:	header length = 20 bytes
	IP:	Type of service = 0
	IP:	Total length = 54 octets
	IP:	Identification = 56869
	IP:	Flags = 0x0000
	IP:		0... .... .... .... = Reserved bit: Not set
	IP:		.0.. .... .... .... = Don't fragment: Not set
	Ip:		..0. .... .... .... = More fragments: Not set
	IP:		...0 0000 0000 0000 = Fragment offset: 0
	IP:	Time to live = 180 seconds/hops
	IP:	Protocol = 6 (TCP)
	IP:	Header checksum = d1f
	IP:	Source Address = 195.244.1.187
	IP:	Destination Address = 1.211.40.56
	IP:

	00000   00 00 0c 9f f5 83 8c 85  90 10 89 d2 08 00 45 00    ..............E.
	00010   00 28 25 de 00 00 40 06  19 92 0a cc b4 74 1f 0d    .(%...@......t..
	00020   5d 13 c3 f4 01 bb 01 d3  28 38 86 f2 6a 57 50 10    ].......(8..jWP.
	00030   10 00 83 6f 00 00                                   ...o.. 	


### References

	For IP and ethernet sniffing: https://www.tcpdump.org/sniffex.c
	For client and Server communication: https://www.geeksforgeeks.org/udp-server-client-implementation-c/
	