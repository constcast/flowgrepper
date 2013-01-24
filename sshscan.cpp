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
#include "sshscan.h"
#include "configobject.h"

SSHscanAnalyzer::SSHscanAnalyzer(const ConfigObject& configObject, ReporterBase& reporter): AnalyzerBase(configObject, reporter), configSection("sshscananalyzer")
{
	std::string bucketsizeString = configObject.getConfString(configSection, "bucketsize_minutes");
	std::string scansString = configObject.getConfString(configSection, "min_scans_per_minute");
	std::string maxpacketsString = configObject.getConfString(configSection, "max_packets");
	std::string minpacketsString = configObject.getConfString(configSection, "min_Packets");

	first_bucket = 500000;
	first_flow = 0;
	interval = atoi(bucketsizeString.c_str()) * 60.0 * 1000.0;
	min_scans = atoi(scansString.c_str()) * atoi(bucketsizeString.c_str());
	minpackets = atoi(minpacketsString.c_str());
	maxpackets = atoi(maxpacketsString.c_str());
}

	
void SSHscanAnalyzer::analyzeFlow(const Flow* flow)
{
	std::map<std::pair<uint32_t, std::pair<uint16_t, std::pair<uint32_t, uint32_t> > >, uint32_t >::iterator it;
//	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, std::map<uint32_t, uint32_t> >::iterator it_list;
//	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int >::iterator it_norev;

	if((flow->packets >= minpackets) && (flow->packets <= maxpackets) && (flow->proto == 6)){

		if(first_flow == 0){
			start_time = flow->flowStart;
			first_flow = 1;
		}

		current_bucket = first_bucket + (long)((flow->flowStart - start_time) / interval);

//		std::cout << "current bucket: " << current_bucket << " start time: " << start_time << " flow start: " << flow->flowStart << std::endl;

		std::pair<uint32_t, uint32_t> current_con = std::make_pair(flow->srcIP, flow->dstIP);

		std::pair<uint32_t, std::pair<uint32_t, uint32_t> > current_con_port = std::make_pair(flow->dstPort, current_con);

		std::pair<uint32_t, std::pair<uint16_t, std::pair<uint32_t, uint32_t> > > current = std::make_pair(current_bucket, current_con_port);
	
		it = data.find(current);
		
//		it_list = data_list.find(current_tuple);
//		it_norev = data_norev.find(current_tuple);

		if(it != data.end()){	
//			std::cout << "existing data update: ";
//			std::cout << "bucket: " << it->first.first << " port: " << it->first.second.first << " src IP: " << convertIP(it->first.second.second.first) << " dst IP: " << convertIP(it->first.second.second.second) << " Count: " << it->second << std::endl;  
			it->second = it->second + 1;
		}
		else {
//			std::cout << "insert new data\n";
//			std::cout << "bucket: " << current.first << " port: " << current.second.first << " src IP: " << convertIP(current.second.second.first) << " dst IP: " << current.second.second.second << std::endl;  
			data.insert(std::make_pair(current, 1));

			//std::vector<uint32_t>* ip = new std::vector<uint32_t>(flow->dstIP);
			//data_list.insert(std::make_pair(current_tuple, *ip));
		}
	}
}


std::string SSHscanAnalyzer::convertIP(uint32_t ip){

	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return inet_ntoa(addr);
}

void SSHscanAnalyzer::passResults()
{
	std::ofstream infofile;
	infofile.open("sshscan.txt");
	
//	std::ofstream infofile_list;
//	infofile_list.open("netscan_list.txt");
	
//	std::ofstream infofile_norev;
//	infofile_norev.open("netscan_norev.txt");


	for(std::map<std::pair<uint32_t, std::pair<uint16_t, std::pair<uint32_t, uint32_t> > >, uint32_t>::iterator it = data.begin(); it != data.end(); ++it) {

		if((it->second) >= min_scans){

			infofile << it->first.first << "\t" << it->first.second.first << "\t" <<  convertIP(it->first.second.second.first) << "\t";
			infofile << convertIP(it->first.second.second.second) << "\t" << it->second << std::endl;
		}
	}
	infofile.close();

}

