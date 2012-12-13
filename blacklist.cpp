#include "blacklist.h"

#include <algorithm>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

Blacklist::Blacklist(const std::string path, unsigned int idx, Type t){

	type = t;
	listname = path;
	index = idx;

	if(type != ONLINE){
		std::string  line;
		std::ifstream stream;

		stream.open(path.c_str());
	
		elements = 0;
		while (std::getline(stream, line)){
			elements++;
		}

		std::cout<< "Number of entries: " << elements <<", index: " << index << ", type: " << type << std::endl;
	
		int len;
		if(type == IP) len = 4; 
		if(type == NET) len = 5;

		ips = (unsigned char*)malloc(elements * len);

		stream.close();

		stream.open(path.c_str());

		int current = 0;
		while (std::getline(stream, line)){

			//std::cout << "Read IP from blacklist: " << line << std::endl;

			char trash[100];
			char * p = new char[line.size() + 1];
			std::copy(line.begin(), line.end(), p);
			p[line.size()] = '\0';

			if((index == 1) && (type == IP)){
				sscanf (p, "%3hhu.%3hhu.%3hhu.%3hhu", ips + (current * 4) + 3, ips + (current * 4) + 2, ips + (current * 4) + 1, ips + (current * 4));
			
			}

			if((index == 2) && (type == IP)){
				sscanf (p, "%s %3hhu.%3hhu.%3hhu.%3hhu", trash, ips + (current * 4) + 3, ips + (current * 4) + 2, ips + (current * 4) + 1, ips + (current * 4));
			}

			if((index == 1) && (type == NET)){
				sscanf (p, "%3hhu.%3hhu.%3hhu.%3hhu/%2hhu", ips + (current * 5) + 3, ips + (current * 5) + 2, ips + (current * 5) + 1, ips + (current * 5), ips + (current * 5) + 4);
			}
			delete p;
			current++;
		}

		stream.close();
	}
}

std::string Blacklist::GetName(){
	return listname;
}

int Blacklist::GetLength(){
	return elements;
}

unsigned char* Blacklist::GetIPs(){
	return ips;
}

int Blacklist::IsIn(uint32_t ip){ 
	
	int result;

	if(type == IP){

		int i;
		for(i = 0; i < elements; i++){
			result = memcmp(ips + (i * 4), &ip, 4);
	
			if(result == 0){

				printf("------------------------------------------------------------MATCH\n");
				printf("comparing %u with %u (result: %i)\n", *((uint32_t*)ips + (i * 4)), ip, result);
				printf("comparing ");
				PrintIP((ips + (i * 4)));
				printf(" with ");
				PrintIP((unsigned char*)&ip);
				printf("\n"); 

				return result;			
			}
			else{
				/*printf("-----------------------------------------------------------------\n");
				printf("comparing %u with %u (result: %i)\n", *((uint32_t*)ips + (i * 4)), ip, result);
				printf("comparing ");
				PrintIP((ips + (i * 4)));
				printf(" with ");
				PrintIP((unsigned char*)&ip);
				printf("\n"); */
			}
		}
	}

	if(type == NET){
		
		int i;
		for(i = 0; i < elements; i++){
			unsigned char* netmask = ips + (i * 5) + 4;

			uint32_t prep_ip = (uint32_t) ip & (uint32_t)(pow(2, 32) - (pow(2, 32 - *netmask))); 
			result = memcmp(ips + (i * 5), &prep_ip, 4);


			
		
			if(result == 0){
				printf("-----------------------------------------------------------------match\n");
				printf("comparing %u with %u (result: %i)\n", *((uint32_t*)ips + (i * 5)), prep_ip, result);
				printf("comparing ");
				PrintNet((ips + (i * 5)));
				printf(" with ");
				PrintIP((unsigned char*)&prep_ip);
				printf(" (");
				PrintIP((unsigned char*)&ip);
				printf(")\n");
				
				return result;

			}
		}
	}

	if(type == ONLINE){

		char query[150];

		sprintf(query, "%hhu.%hhu.%hhu.%hhu.%s", *(((unsigned char*)&ip) + 0), *(((unsigned char*)&ip) + 1), *(((unsigned char*)&ip) + 2), *(((unsigned char*)&ip) + 3), listname.c_str());
		printf("Do query: %s\n", query);
		
		//struct hostent* he = gethostbyname("165.11.175.178.zen.spamhaus.org");
		struct hostent* he = gethostbyname(query);
		if(!he){
			//printf("Cannot find hostname\n");
			return -1;
		}
		else{
			int i = 0;
			while(he->h_addr_list[i] != NULL){
				printf("%s ", inet_ntoa(*(struct in_addr*)(he->h_addr_list[i])));
				i++;

				if(inet_ntoa(*(struct in_addr*)(he->h_addr_list[i])) != "127.0.0.2") return 0;
			}
		}
	}

	return -1;
}


void Blacklist::PrintIP(unsigned char* ip){
	printf("IP: %hhu.%hhu.%hhu.%hhu ", *(ip + 3), *(ip + 2), *(ip + 1), *ip);  
}


void Blacklist::PrintNet(unsigned char* net){
	printf("net: %hhu.%hhu.%hhu.%hhu/%hhu ", *(net + 3), *(net + 2), *(net + 1), *net, *(net + 4));  
}
