
/*
 * Author: Sudhindra Gopal Krishna
 * Email: sudhi@ou.edu
 * Data Network
 * Project 1
 * Client Side
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "pcap_server.h"
#define port 8081


/*
 * Part of the code was referred from 
 * https://www.geeksforgeeks.org/udp-server-client-implementation-c/
 */

int main(int argc, const char *argv[])
{
	int sockfd;
	struct sockaddr_in servaddr;
	u_char *data;
	char errBuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const char *fname = argv[1];	


	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}
	

	memset(&servaddr, 0, sizeof(servaddr));

	//server information
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(port);

	int n;
	socklen_t len;

	// Read the Pcap file
	pcap_t *handle = pcap_open_offline(fname, errBuff);

	// Obtain the information of each frame of the captured packet one at a time.
	int returnValue = pcap_next_ex(handle, &header, &data);

	int capturedLen = header->caplen; // Total length of the captured data
	int counter = 0;
	ip = (struct sniffIP*)(data + 16);
	char *myIP = "10.0.0.1";
	while(returnValue >= 0){
		
		/*
		 * This part of the code reads through all the packets 
		 * and make sures to process only TCP or UDP IPv4 packets
		 */

		// for(int i = 0; i < header->caplen; i++){
		// if(strcmp(inet_ntoa(ip->ip_src), myIP)==0){
				// // printf("%s\n",inet_ntoa(ip->ip_src));
				// data[24] = 0x0a;
				// printf("%d\n",ip->ip_ttl);

				// data[i] = counter;
				// if(counter%255 == 0){	
				// 	data[i] = 255;
				// 	data[++i] = counter%255;
				// }
				
				sendto(sockfd, (const char*)data, 4096, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
			
		// }

		returnValue = pcap_next_ex(handle, &header, &data);

	}
	// printf("%d\n",counter);
	close(sockfd);
}