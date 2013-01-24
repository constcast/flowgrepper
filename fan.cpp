#include "fan.h"

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

#include "flow.h"
#include "reporterbase.h"
#include "configobject.h"

FanAnalyzer::FanAnalyzer(const ConfigObject& configObject, ReporterBase& reporter): AnalyzerBase(configObject, reporter), configSection("fananalyzer")
{
	std::string bucketsizeString = configObject.getConfString(configSection, "bucketsize_minutes");
	std::string minfanoutString = configObject.getConfString(configSection, "min_fanout");
	std::string minfaninString = configObject.getConfString(configSection, "min_fanin");
	std::string protocolString = configObject.getConfString(configSection, "protocol");

	first_bucket = 500000;
	first_flow = 0;
	interval = atoi(bucketsizeString.c_str()) * 60.0 * 1000.0;
	min_fanout = atoi(minfanoutString.c_str());
	min_fanin = atoi(minfaninString.c_str());
	protocol = atoi(protocolString.c_str());
}

	
void FanAnalyzer::analyzeFlow(const Flow* flow)
{

//	std::map<std::pair<uint32_t, uint32_t>, uint32_t>::iterator it_out;
	std::map<std::pair<uint32_t, uint32_t>, struct info>::iterator it_out;
	std::map<std::pair<uint32_t, uint32_t>, uint32_t>::iterator it_in;

	if(flow->proto == protocol){

		if(first_flow == 0){
			start_time = flow->flowStart;
			first_flow = 1;
		}

		current_bucket = first_bucket + (long)((flow->flowStart - start_time) / interval);
		std::cout << "current bucket: " << current_bucket << " start time: " << start_time << " flow start: " << flow->flowStart << std::endl;

		std::pair<uint32_t, uint32_t> current_out = std::make_pair(current_bucket, flow->srcIP);
		std::pair<uint32_t, uint32_t> current_in = std::make_pair(current_bucket, flow->dstIP);
	
		it_out = data_out.find(current_out);
		it_in = data_in.find(current_in);

		if(it_out != data_out.end()){	
			std::cout << "(OUT) existing data update: ";
			std::cout << "bucket: " << it_out->first.first << " IP: " << convertIP(it_out->first.second) << " Count: " /* << it_out->second */ << std::endl;  
//			it_out->second = it_out->second + 1;
			it_out->second.bytes = it_out->second.bytes + flow->bytes;
			it_out->second.packets = it_out->second.packets + flow->packets;
			it_out->second.revbytes = it_out->second.revbytes + flow->revBytes;
			it_out->second.revpackets = it_out->second.revpackets + flow->revPackets;
			it_out->second.flows = it_out->second.flows + 1;
		}
		else {
			std::cout << "(OUT) insert new data\n";
			std::cout << "bucket: " << current_out.first << " IP: " << convertIP(current_out.second) << std::endl;  
			
			struct info i;
			i.bytes = flow->bytes;
			i.packets = flow->packets;
			i.revbytes = flow->revBytes;
			i.revpackets = flow->revPackets;
			i.flows = 1;

			data_out.insert(std::make_pair(current_out, i));
		}

		if(it_in != data_in.end()){	
			std::cout << "(IN) existing data update: ";
			std::cout << "bucket: " << it_in->first.first << " IP: " << convertIP(it_in->first.second) << " Count: " << it_in->second << std::endl;  
			it_in->second = it_in->second + 1;
		}
		else {
			std::cout << "(IN) insert new data\n";
			std::cout << "bucket: " << current_in.first << " IP: " << convertIP(current_in.second) << std::endl;  
			data_in.insert(std::make_pair(current_in, 1));
		}
	}
	else {
		std::cout << "flow has wrong protocol: " << (uint32_t)flow->proto << std::endl;
	}
}


std::string FanAnalyzer::convertIP(uint32_t ip){

	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return inet_ntoa(addr);
}

void FanAnalyzer::passResults()
{
	std::ofstream infofile_out;
	infofile_out.open("fanout.txt");
	
	std::ofstream infofile_in;
	infofile_in.open("fanin.txt");
	
	for(std::map<std::pair<uint32_t, uint32_t>, struct info>::iterator it = data_out.begin(); it != data_out.end(); ++it) {

		if((it->second.bytes) >= min_fanout){

			infofile_out << it->first.first << "\t" <<  convertIP(it->first.second) << "\t" << it->second.bytes << "\t" << it->second.packets << "\t";
			infofile_out << it->second.revbytes << "\t" <<it->second.revpackets << "\t" << it->second.flows << "\t";

			if(it->second.revbytes > 0){
				infofile_out << (float)it->second.bytes / (float)it->second.revbytes << "\t";
				infofile_out << (float)it->second.packets / (float)it->second.revpackets << "\t";
				infofile_out << ((float)it->second.bytes / (float)it->second.revbytes) - ((float)it->second.packets / (float)it->second.revpackets);
				
			}
			else {
				infofile_out << it->second.bytes << "\t" << it->second.packets << "\t" <<"100000000";
			}
			infofile_out << std::endl;
		}
	}
	infofile_out.close();

	for(std::map<std::pair<uint32_t, uint32_t>, uint32_t>::iterator it = data_in.begin(); it != data_in.end(); ++it) {

		if((it->second) >= min_fanin){

		infofile_in << it->first.first << "\t" <<  convertIP(it->first.second) << "\t" << it->second << std::endl;
		}
	}
	infofile_out.close();
	infofile_in.close();
}

