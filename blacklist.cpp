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

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

Blacklist::Blacklist(const std::string path, unsigned int idx, Type t){
	tree = lpm_init();
	
	type = t;
	listname = path;
	index = idx;

	if(type == LIST){
		std::string  line;
		std::ifstream stream;

		stream.open(path.c_str());
	
		elements = 0;
		while (std::getline(stream, line)){
			elements++;
		}

		std::cout<< "Number of entries: " << elements <<", index: " << index << ", type: " << type << std::endl;
	
		stream.close();

		stream.open(path.c_str());

		int mask;
		std::string ipAddress;

		while (std::getline(stream, line)){

			size_t col = 0;
			for(int i = 1; i < index; i++){
				col = line.find(" ", col);
				col++;
			}

			//int mask;
			size_t pos = line.find("/", col); 
			//std::string ipAddress;
		
			if (pos == std::string::npos) {
				mask = 32;
				size_t end = line.find(" ", col);
				if(end > line.size()) end = line.size();
				ipAddress = line.substr(col, end - col);	
				//std::cout << " len: " << end << " " << col <<std::endl;
			} else {
				ipAddress = line.substr(col, pos - col);
				//mask = atoi(line.substr(pos, line.size()).c_str());
				size_t end = line.find(" ", col + 1);
				mask = atoi(line.substr(pos + 1, (end - pos)).c_str());
			}
			//std::cout << "ip:"<< ipAddress << " mask:" << mask << std::endl;
			lpm_insert(tree, ipAddress.c_str(), mask);
		}
		std::cout << "Test format: ip:"<< ipAddress << " mask:" << mask << std::endl;
		stream.close();
	}
}

std::string Blacklist::GetName(){
	return listname;
}

int Blacklist::GetLength(){
	return elements;
}

int Blacklist::IsIn(uint32_t ip, char** out){ 

	if(type == LIST){
		static char output[16];

		lpm_lookup(tree, ip, output);
		strncpy(*out, output, 16);
		//std::cout << "Checking IP: " << ip << " result: "  << output << std::endl;

		if (strncmp(output, "NF", 3) == 0) {
			//std::cerr << " found" << ip <<"\t"  << output << std::endl;
			return 1;
		} else {
			//std::cerr << "found" << std::endl;
			//std::cerr << output <<"\t"  << "NF" << std::endl;
			return 0;
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

				if(std::string(inet_ntoa(*(struct in_addr*)(he->h_addr_list[i]))) != std::string("127.0.0.2")) return 1;
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
