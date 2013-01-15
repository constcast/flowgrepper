#include "dnsbl.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>  
#include <string>

#include <fstream>
#include <sstream>
#include <iterator>
#include <utility>
//#include <tr1/tuple>

#include "flow.h"
#include "reporterbase.h"
#include "netscan.h"
#include "configobject.h"

NetscanAnalyzer::NetscanAnalyzer(const ConfigObject& configObject, ReporterBase& reporter): AnalyzerBase(configObject, reporter), configSection("netscananalyzer")
{
	std::string bucketsizeString = configObject.getConfString(configSection, "bucketsize_minutes");
	std::string scansString = configObject.getConfString(configSection, "min_scans_per_minute");

	first_bucket = 500000;
	first_flow = 0;
	interval = atoi(bucketsizeString.c_str()) * 60.0 * 1000.0;
	min_scans = atoi(scansString.c_str()) * atoi(bucketsizeString.c_str());
}

	
void NetscanAnalyzer::analyzeFlow(const Flow* flow)
{
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int >::iterator it;
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, std::map<uint32_t, uint32_t> >::iterator it_list;
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int >::iterator it_norev;

	if((flow->packets <= 3) && (flow->proto == 6)){

		if(first_flow == 0){
			start_time = flow->flowStart;
			first_flow = 1;
		}

		current_bucket = first_bucket + (long)((flow->flowStart - start_time) / interval);

		std::cout << "current bucket: " << current_bucket << " start time: " << start_time << " flow start: " << flow->flowStart << std::endl;

		std::pair<uint32_t, uint16_t> current = std::make_pair(flow->srcIP, flow->dstPort);

		std::pair<uint32_t, std::pair<uint32_t, uint16_t> > current_tuple = std::make_pair(current_bucket, current);
	
		it = data.find(current_tuple);
		it_list = data_list.find(current_tuple);
		it_norev = data_norev.find(current_tuple);

		if(it != data.end()){	
			std::cout << "existing data update: ";
			std::cout << "bucket: " << it->first.first << " IP: " << convertIP(it->first.second.first) << " Port: " << it->first.second.second << " Count: " << it->second << std::endl;  
			it->second = it->second + 1;
		}
		else {
			std::cout << "insert new data\n";
			std::cout << "bucket: " << current_tuple.first << " IP: " << convertIP(current_tuple.second.first) << " Port: " << current_tuple.second.second << std::endl;  
			data.insert(std::make_pair(current_tuple, 1));

			//std::vector<uint32_t>* ip = new std::vector<uint32_t>(flow->dstIP);
			//data_list.insert(std::make_pair(current_tuple, *ip));
		}

		if(it_list != data_list.end()){
/*			std::cout << "push back" << std::endl;
			it_list->second.push_back(flow->dstIP); */

			std::map<uint32_t, uint32_t>::iterator it_map;
			it_map = it_list->second.find(flow->dstIP);

			if(it_map != it_list->second.end()){
				std::cout << "update ip count " << std::endl;
				it_map->second = it_map->second + 1;
			}
			else{
				std::cout << "insert new destination IP" << std::endl;
				it_list->second.insert(std::make_pair(flow->dstIP, 1));
			}

		}
		else{

			std::map<uint32_t, uint32_t>* ip = new std::map<uint32_t, uint32_t>();

			ip->insert(std::make_pair(flow->dstIP, 1));
			
			data_list.insert(std::make_pair(current_tuple, *ip));
		}

		
		if(flow->revPackets <= 2){

			if(it_norev != data_norev.end()){	
				std::cout << "norev: existing data update: ";
				std::cout << "bucket: " << it_norev->first.first << " IP: " << convertIP(it_norev->first.second.first) << " Port: " << it_norev->first.second.second << " Count: " << it_norev->second << std::endl;  
				it_norev->second = it_norev->second + 1;
			}
			else {
				std::cout << "norev: insert new data\n";
				std::cout << "bucket: " << current_tuple.first << " IP: " << convertIP(current_tuple.second.first) << " Port: " << current_tuple.second.second << std::endl;  
				data_norev.insert(std::make_pair(current_tuple, 1));
			}
		}
	}
	else {
		std::cout << "flow has to many packets: " << flow->packets << " or wrong protocol: " << (uint32_t)flow->proto << " or to many reverse packets: " << flow->revPackets << std::endl;
	}
}


std::string NetscanAnalyzer::convertIP(uint32_t ip){

	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return inet_ntoa(addr);
}

void NetscanAnalyzer::passResults()
{
	std::ofstream infofile;
	infofile.open("netscan.txt");
	
	std::ofstream infofile_list;
	infofile_list.open("netscan_list.txt");
	
	std::ofstream infofile_norev;
	infofile_norev.open("netscan_norev.txt");


	for(std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int>::iterator it = data.begin(); it != data.end(); ++it) {

		if((it->second) >= min_scans){

			int no_rev = 0;
			float percentage = 0.0;
			std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int >::iterator it_norev;

			it_norev = data_norev.find(it->first);

			if(it_norev != data_norev.end()){
				no_rev = it_norev->second;
				percentage = (float)no_rev / (float)it->second * 100.0; 
			}
	
			infofile << it->first.first << "\t" <<  convertIP(it->first.second.first) << "\t" << it->first.second.second << "\t" << it->second << "\t" << percentage << "\t" << no_rev << std::endl;
		}
	}
	infofile.close();

	for(std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int>::iterator it = data_norev.begin(); it != data_norev.end(); ++it) {
		
		infofile_norev << it->first.first << "\t" <<  convertIP(it->first.second.first) << "\t" << it->first.second.second << "\t" << it->second << std::endl;

	}
	infofile_norev.close();

	for(std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, std::map<uint32_t, uint32_t> >::iterator it = data_list.begin(); it != data_list.end(); ++it) {
		
		if((it->second.size()) >= (unsigned int)min_scans){
			infofile_list << it->first.first << "\t" <<  convertIP(it->first.second.first) << "\t" << it->first.second.second << "\t" << it->second.size() << "\t";

			for(std::map<uint32_t, uint32_t>::iterator it_vec = it->second.begin(); it_vec != it->second.end(); it_vec++){
				infofile_list << convertIP(it_vec->first) << "\t" << it_vec->second << "\t";
			}	

			infofile_list << std::endl;
		}
	}
	infofile_list.close(); 

}

