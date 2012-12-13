#include "dnsbl.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>  
#include <string>

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
		if(*bl_names == "ip") t = IP;
		if(*bl_names == "net") t = NET;
		if(*bl_names == "online") t = ONLINE;

		bl = new Blacklist(name, index, t);
		blacklist.push_back(*bl);
	}
}

	
void DNSblAnalyzer::analyzeFlow(const Flow* flow)
{
	std::vector<Blacklist>::iterator it;

	for (it = blacklist.begin(); it != blacklist.end(); ++it){
			
		if(it->IsIn(flow->srcIP) == 0){

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
		}	
	}
}

void DNSblAnalyzer::passResults()
{

	for(std::map<uint32_t, blackinfo>::iterator it = finding.begin(); it != finding.end(); ++it) {
		std::stringstream stream;
		
		struct in_addr addr;
		addr.s_addr = htonl(it->first);

		stream << "IP: " << inet_ntoa(addr) << "\tList: " << it->second.listname << "\tCount: " << it->second.count;
		reporter.addLogString(stream.str());
	} 
}

