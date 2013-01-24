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

#include "flow.h"
#include "reporterbase.h"
#include "blacklist.h"
#include "configobject.h"

DNSblAnalyzer::DNSblAnalyzer(const ConfigObject& configObject, ReporterBase& reporter): AnalyzerBase(configObject, reporter), configSection("dnsblanalyzer")
{
	Blacklist* bl = NULL;
	std::vector<std::string>::iterator bl_names;
	std::vector<std::string> lists;

	int index;
	Type t;
	c = 0;
	fl_count = 0;
	
	std::string blacklistsString = configObject.getConfString(configSection, "blacklists");

	std::istringstream blstream(blacklistsString);
	std::copy(std::istream_iterator<std::string>(blstream), std::istream_iterator<std::string>(), std::back_inserter<std::vector<std::string> >(lists));

	for (bl_names = lists.begin(); bl_names != lists.end(); ++bl_names){
		std::cout << "preparing blacklist " << *bl_names << std::endl;
		
		std::string name = *bl_names;
		
		bl_names++;
		std::stringstream ss(*bl_names);
		ss >> index;

		bl_names++;
		//if(*bl_names == "ip") t = IP;
		//if(*bl_names == "net") t = NET;
		if(*bl_names == "online") t = ONLINE;
		if(*bl_names == "list") t = LIST;

		bl = new Blacklist(name, index, t);
		blacklist.push_back(*bl);
	}
}

	
void DNSblAnalyzer::analyzeFlow(const Flow* flow)
{
	std::vector<Blacklist>::iterator it;
	fl_count++;

	for (it = blacklist.begin(); it != blacklist.end(); ++it){

		InsertFinding(it, flow->srcIP, flow);
		InsertFinding(it, flow->dstIP, flow);
			
/*		if(it->IsIn(flow->srcIP) == 0){

			std::map<uint32_t, blackinfo>::iterator i;
			i = finding.find(flow->srcIP);

			//empty
			if(i == finding.end()){
				
				struct blackinfo bi;
				bi.count = 1;
				bi.listname = it->GetName();
				
				finding[flow->srcIP] = bi;
				break;
			}
			//already in map
			else{
				//i->second.listname += " " + it->GetName();
				i->second.count += 1;
				break;
			}					
		}	*/
	} 
}

void DNSblAnalyzer::InsertFinding(std::vector<Blacklist>::iterator it, uint32_t ip, const Flow* flow){
	
	char *out;
	out = (char*)malloc(16*sizeof(char));

	if(it->IsIn(ip, &out) == 0){
		c++;
	//	std::cout << "DEBUG " << std::string(out) << std::endl;
		std::map<uint32_t, blackinfo>::iterator i;
		i = finding.find(ip);

		struct Dataset ds;
		ds.blackip = ip;
		if(ip == flow->srcIP) {
			ds.ip = flow->dstIP;
			ds.direction = 0;
		}
		if(ip == flow->dstIP){
			ds.ip = flow->srcIP;
			ds.direction = 1;
		}

		ds.fl = *flow;
		ds.blacklist_name = it->GetName();

		dataset.push_back(ds);

		//empty
		if(i == finding.end()){
	
			struct blackinfo bi;
			bi.count = 1;
			bi.listname = it->GetName();
			finding[ip] = bi;

			InsertPort(flow->srcPort, flow->proto);

			return;										                        }
		//already in map
		else{
			//i->second.listname += " " + it->GetName();
			i->second.count += 1;
			InsertPort(flow->srcPort, flow->proto);
			return;
		}
	}
	free(out);
}

void DNSblAnalyzer::InsertPort(uint16_t port, uint8_t proto){
	
	std::map<uint16_t, unsigned int>::iterator port_it_tcp;
	std::map<uint16_t, unsigned int>::iterator port_it_udp;

	
	/*if(port_it_tcp == ports_tcp.end()){
		ports_tcp[port] = 1;
	}
	else{
		//ports_it_tcp->second += 1;
	}*/
}

std::string ConvertIP(uint32_t ip){

	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return inet_ntoa(addr);
}

void DNSblAnalyzer::passResults()
{
	std::ofstream infofile;
	infofile.open("infofile.txt");


	for(std::map<uint32_t, blackinfo>::iterator it = finding.begin(); it != finding.end(); ++it) {
		std::stringstream stream;

		
		struct in_addr addr;
		addr.s_addr = htonl(it->first);

		stream << "IP: " << inet_ntoa(addr) << "\tList: " << it->second.listname << "\tCount: " << it->second.count;
		infofile << inet_ntoa(addr) <<"\t" << it->second.count << std::endl;

		reporter.addLogString(stream.str());

	}
	infofile.close();

	std::ofstream blackflows_src;
	blackflows_src.open("blackflows_src.txt");

	std::ofstream blackflows_dst;
	blackflows_dst.open("blackflows_dst.txt");


	std::vector<Dataset>::iterator ds_it;
	for (ds_it = dataset.begin(); ds_it != dataset.end(); ++ds_it){

		struct Dataset ds = *ds_it;

		std::string dir;
		if(ds.direction == 0){
			dir = "black=src";
			uint32_t proto = (uint32_t)ds.fl.proto;
			blackflows_src << ConvertIP(ds.ip) << "\t" << ConvertIP(ds.blackip) <<"\t";
	                //blackflows_src << ds.direction   << "\t";
	                blackflows_src << ds.fl.flowStart << "\t" << ds.fl.flowEnd <<"\t";
	                blackflows_src << ds.fl.srcPort << "\t" << ds.fl.dstPort << "\t" << "\t";
	                blackflows_src << ds.fl.packets << "\t" << ds.fl.bytes << "\t";
	                blackflows_src << ds.fl.revPackets << "\t" << ds.fl.revBytes << "\t";
	                blackflows_src << ds.blacklist_name <<"\t" << proto << std::endl;
		}
		if(ds.direction == 1){
			dir = "black=dst";
			uint32_t proto = (uint32_t)ds.fl.proto;
			blackflows_dst << ConvertIP(ds.ip) << "\t" << ConvertIP(ds.blackip) <<"\t";
                        //blackflows_dst << ds.direction   << "\t";
                        blackflows_dst << ds.fl.flowStart << "\t" << ds.fl.flowEnd <<"\t";
                        blackflows_dst << ds.fl.srcPort << "\t" << ds.fl.dstPort << "\t" << "\t";
                        blackflows_dst << ds.fl.packets << "\t" << ds.fl.bytes << "\t";
                        blackflows_dst << ds.fl.revPackets << "\t" << ds.fl.revBytes << "\t";
                        blackflows_dst << ds.blacklist_name <<"\t" << proto << std::endl;
		}

/*
		std::stringstream proto;
		proto << ds.fl.proto;
		   

		//blackflows << ds.fl.flowStart << "\t" << ds.fl.flowEnd <<"\t"; 
		blackflows << ConvertIP(ds.ip) << "\t" << ConvertIP(ds.blackip) <<"\t"; 
		blackflows << ds.direction   << "\t";	
		blackflows << ds.fl.flowStart << "\t" << ds.fl.flowEnd <<"\t"; 
		blackflows << ds.fl.srcPort << "\t" << ds.fl.dstPort << "\t" << "\t";
		blackflows << ds.fl.packets << "\t" << ds.fl.bytes << "\t";
		blackflows << ds.fl.revPackets << "\t" << ds.fl.revBytes << "\t";
		blackflows << ds.blacklist_name <<"\t" << ds.fl.proto << std::endl;
*/

	}

	blackflows_src.close();
	blackflows_dst.close();

	std::cout << "count found: " << c << "sum: " << fl_count << std::endl;

	/*
	std::ofstream infofile_sort;
	infofile_sort.open("infofile_sort.txt");
	
	unsigned int maxval = 0;
	uint32_t maxip;
	int count = 0;
	while(!finding.empty()){
	maxval = 0;
	for(std::map<uint32_t, blackinfo>::iterator it = finding.begin(); it != finding.end(); it++){
		if(it->second.count > maxval){
			maxval = it->second.count;
			maxip = it->first;
		}
	}

	finding.erase(maxip);

	struct in_addr addr;
	addr.s_addr = htonl(maxip);
	
	infofile_sort << inet_ntoa(addr) << "\t" << maxval << std::endl;
	}
	infofile_sort.close();
	*/

}

