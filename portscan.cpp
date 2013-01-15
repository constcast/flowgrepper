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
#include "portscan.h"
#include "configobject.h"

PortscanAnalyzer::PortscanAnalyzer(const ConfigObject& configObject, ReporterBase& reporter): AnalyzerBase(configObject, reporter), configSection("portscananalyzer")
{
	std::string bucketsizeString = configObject.getConfString(configSection, "bucketsize_minutes");
	std::string scansString = configObject.getConfString(configSection, "min_scans_per_minute");
	std::string extendString = configObject.getConfString(configSection, "separat_sourceport");
	std::string highportString = configObject.getConfString(configSection, "highport_sourceport");
	std::string maxoutString = configObject.getConfString(configSection, "max_out_packets");
	std::string protocolString = configObject.getConfString(configSection, "protocol_number");

	first_bucket = 500000;
	first_flow = 0;
	interval = atoi(bucketsizeString.c_str()) * 60.0 * 1000.0;
	min_scans = atoi(scansString.c_str()) * atoi(bucketsizeString.c_str());
	extended = atoi(extendString.c_str());
	highport = atoi(highportString.c_str());
	max_out_packets = atoi(maxoutString.c_str());
	protocol = atoi(protocolString.c_str());
}

	
void PortscanAnalyzer::analyzeFlow(const Flow* flow)
{
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint32_t> >, int >::iterator it;
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint32_t> >, std::map<uint16_t, uint32_t> >::iterator it_list;
	
	std::map<std::pair<uint32_t, std::pair<uint16_t, std::pair<uint32_t, uint32_t> > >, std::map<uint16_t, uint32_t> >::iterator it_extended;

//	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int >::iterator it_norev;

	if((flow->packets <= max_out_packets) && (flow->proto == protocol) && (flow->srcPort >= highport)){

		if(first_flow == 0){
			start_time = flow->flowStart;
			first_flow = 1;
		}

		current_bucket = first_bucket + (long)((flow->flowStart - start_time) / interval);

		std::cout << "current bucket: " << current_bucket << " start time: " << start_time << " flow start: " << flow->flowStart << std::endl;

		std::pair<uint32_t, uint32_t> current = std::make_pair(flow->srcIP, flow->dstIP);

		std::pair<uint32_t, std::pair<uint32_t, uint32_t> > current_tuple = std::make_pair(current_bucket, current);

		it = data.find(current_tuple);
		it_list = data_list.find(current_tuple);
//		it_norev = data_norev.find(current_tuple);


		if(it != data.end()){	
			std::cout << "existing data update: ";
			std::cout << "bucket: " << it->first.first << " Source IP: " << convertIP(it->first.second.first) << " Destination IP: " << convertIP(it->first.second.second) << " Count: " << it->second << std::endl;  
			it->second = it->second + 1;
		}
		else {
			std::cout << "insert new data: ";
			std::cout << "bucket: " << current_tuple.first << " Source IP: " << convertIP(current_tuple.second.first) << " Destination IP: " << convertIP(current_tuple.second.second) << std::endl;  
			data.insert(std::make_pair(current_tuple, 1));

			//std::vector<uint32_t>* ip = new std::vector<uint32_t>(flow->dstIP);
			//data_list.insert(std::make_pair(current_tuple, *ip));
		}
	
		if(it_list != data_list.end()){

			std::map<uint16_t, uint32_t>::iterator it_map;
			it_map = it_list->second.find(flow->dstPort);

			if(it_map != it_list->second.end()){
				std::cout << "update ip count " << std::endl;
				it_map->second = it_map->second + 1;
			}
			else{
				std::cout << "insert new destination IP" << std::endl;
				it_list->second.insert(std::make_pair(flow->dstPort, 1));
			}

		}
		else{

			std::map<uint16_t, uint32_t>* ip = new std::map<uint16_t, uint32_t>();

			ip->insert(std::make_pair(flow->dstPort, 1));
			
			data_list.insert(std::make_pair(current_tuple, *ip));
		}

		if(extended == 1){

			std::pair<uint16_t, std::pair<uint32_t, uint32_t> > con = std::make_pair(flow->srcPort, current);
			std::pair<uint32_t, std::pair<uint16_t, std::pair<uint32_t, uint32_t> > > current_extended = std::make_pair(current_bucket, con);

			it_extended = data_extended.find(current_extended);
		
			if(it_extended != data_extended.end()){
				std::map<uint16_t, uint32_t>::iterator it_map;
                	        it_map = it_extended->second.find(flow->dstPort);

                        	if(it_map != it_extended->second.end()){
					std::cout << "update ip count " << std::endl;
					it_map->second = it_map->second + 1;
				}
				else{
					std::cout << "insert new destination IP" << std::endl;
					it_list->second.insert(std::make_pair(flow->dstPort, 1));
				}

			}
			else{
				std::map<uint16_t, uint32_t>* ip = new std::map<uint16_t, uint32_t>();

				ip->insert(std::make_pair(flow->dstPort, 1));

				data_extended.insert(std::make_pair(current_extended, *ip));

			}
		}

/*		
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
		} */
	}
	else {
		std::cout << "flow has to many packets: " << flow->packets << " or wrong protocol: " << (uint32_t)flow->proto << " or to many reverse packets: " << flow->revPackets << std::endl;
	} 
}


std::string PortscanAnalyzer::convertIP(uint32_t ip){

	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return inet_ntoa(addr);
}

void PortscanAnalyzer::passResults()
{
	std::ofstream infofile;
	infofile.open("portscan.txt");
	
	std::ofstream infofile_list;
	infofile_list.open("portscan_list.txt");
	
	std::ofstream picture;
	picture.open("portscan_pic.pgm");

	for(std::map<std::pair<uint32_t, std::pair<uint32_t, uint32_t> >, int>::iterator it = data.begin(); it != data.end(); ++it) {

		if((it->second) >= min_scans){

			int no_rev = 0;
			float percentage = 0.0;
			//std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int >::iterator it_norev;

			/* it_norev = data_norev.find(it->first);

			if(it_norev != data_norev.end()){
				no_rev = it_norev->second;
				percentage = (float)no_rev / (float)it->second * 100.0; 
			} */
	
			infofile << it->first.first << "\t" <<  convertIP(it->first.second.first) << "\t" << convertIP(it->first.second.second) << "\t" << it->second << "\t" << percentage << "\t" << no_rev << std::endl;
		}
	}
	infofile.close();

/*	for(std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int>::iterator it = data_norev.begin(); it != data_norev.end(); ++it) {
		
		infofile_norev << it->first.first << "\t" <<  convertIP(it->first.second.first) << "\t" << it->first.second.second << "\t" << it->second << std::endl;

	}
	infofile_norev.close();
*/

	picture << "P2" << std::endl;
	picture << "65535" << std::endl;
	picture << data_list.size() << std::endl;
	picture << "1" << std::endl;

	int last;

	for(std::map<std::pair<uint32_t, std::pair<uint32_t, uint32_t> >, std::map<uint16_t, uint32_t> >::iterator it = data_list.begin(); it != data_list.end(); ++it) {

		last = 1;
		
		if((it->second.size()) >= (unsigned int)min_scans){
			infofile_list << it->first.first << "\t" <<  convertIP(it->first.second.first) << "\t" << convertIP(it->first.second.second) << "\t" << it->second.size() << "\t";

			for(std::map<uint16_t, uint32_t>::iterator it_vec = it->second.begin(); it_vec != it->second.end(); it_vec++){
				infofile_list << it_vec->first << "\t" << it_vec->second << "\t";

				for(int i = last; i < it_vec->first; i++){
					picture << "0";
				}

				picture << "1";  
				last = it_vec->first;
			}

			for(int i = 1; i <= (65535 - last); i++){
				picture << "0";
			}

			picture << std::endl;
			infofile_list << std::endl;
		}
	}
	infofile_list.close(); 
	picture.close();

	if(extended == 1){

		std::ofstream infofile_extended;
		infofile_extended.open("portscan_extended.txt");

		for(std::map<std::pair<uint32_t, std::pair<uint16_t, std::pair<uint32_t, uint32_t> > >, std::map<uint16_t, uint32_t> >::iterator it = data_extended.begin(); it != data_extended.end(); ++it) {
		
			if((it->second.size()) >= (unsigned int)min_scans){
				infofile_extended << it->first.first << "\t" << it->first.second.first << "\t" <<  convertIP(it->first.second.second.first) << "\t" << convertIP(it->first.second.second.second) << "\t" << it->second.size() << "\t";

				for(std::map<uint16_t, uint32_t>::iterator it_vec = it->second.begin(); it_vec != it->second.end(); it_vec++){
					infofile_extended << it_vec->first << "\t" << it_vec->second << "\t";
				}	

				infofile_extended << std::endl;
			}
		}
		infofile_extended.close(); 
	}
}

