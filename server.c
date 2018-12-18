/*
 * Author: Sudhindra Gopal Krishna
 * Email: sudhi@ou.edu
 * Data Network
 * Project 1
 * Server Side
 */

#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include "pcap_server.h"


#define port 8081
#define maxLine 18000

/*
 * Part of the code was referred from 
 * https://www.geeksforgeeks.org/udp-server-client-implementation-c/
 */

int main(int argc, const char *argv[]){

	int sockfd;
	char buffer[maxLine];
	char caplen[10];
	struct sockaddr_in servaddr, cliaddr;
	int n;
	const u_char *data;
	struct sniffIp *ip;
	socklen_t len;

	//creating socket
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));
	
	//server information
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(port);

	if( bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		perror("Binding failed");
		exit(EXIT_FAILURE);
	}
	//Receive the data from the client

	while(1){
		n = recvfrom(sockfd, (u_char *)buffer, 18000, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
		buffer[n] = '\0';

		// Process the data receieved and print them.
		// printEther(buffer);			
		printIP(buffer);
		printData(buffer);
	}
	return 0;

	
}