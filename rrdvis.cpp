#include "rrdvis.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <sstream>
#include <iostream>
#include <fstream>
#include <stdexcept>

#include "flow.h"
#include "reporterbase.h"


RRDVisAnalyzer::RRDVisAnalyzer(const ConfigObject& configObject, ReporterBase& reporter)
	: AnalyzerBase(configObject, reporter), configSection("rrdvisualizer")
{
	configFile = configObject.getConfString(configSection, "configfile");
	rrdPath    = configObject.getConfString(configSection, "rrdtool_path");
	rrdDbPath  = configObject.getConfString(configSection, "db_path");

	// parse subnet config file
	std::ifstream subnetConfig(configFile.c_str());
	std::string token;
	bool subnet = true;
	std::string subnet_string;

	tree = lpm_init();

	std::vector<std::string> subnetList;

	while (subnetConfig) {
		subnetConfig >> token;
		if (subnet) {
			subnet_string = token;
			subnet = false;
		} else {
			size_t pos = subnet_string.find("/");
			if (pos == std::string::npos) {
				throw std::runtime_error("Error: Cannot parse subnet \"" + subnet_string + "\"");
			}
			std::string ip   = subnet_string.substr(0, pos);
			std::string mask = subnet_string.substr(pos + 1, subnet_string.size());

			rrdDbMa[subnet_string] = token;

			lpm_insert(tree, ip.c_str(), atoi(mask.c_str()));
			
			subnet = true;
		}
	}

}

RRDVisAnalyzer::~RRDVisAnalyzer()
{
	lpm_destroy(tree);	
}

void RRDVisAnalyzer::updateEntry(const std::string &subnet, uint64_t timestamp, uint64_t inbytes, uint64_t inpackets, uint64_t outbytes, uint64_t outpackets)
{
	if (subnetList.find(subnet) == subnetList.end()) {
		TimeSubnetStats s;
		subnetList[subnet] = s;
	}
	TimeSubnetStats& stats = subnetList.find(subnet)->second;
	if (stats.find(timestamp) == stats.end()) {
		SubnetStats s;
		memset(&s, 0, sizeof(s));
		stats[timestamp] = s;
	}
	SubnetStats& subnetStats = stats.find(timestamp)->second;
	subnetStats.out_bytes   += outbytes;
	subnetStats.in_bytes    += inbytes;
	subnetStats.out_packets += outpackets;
	subnetStats.in_packets  += inpackets;
}

void RRDVisAnalyzer::analyzeFlow(const Flow* flow)
{
	static char output[16];
	lpm_lookup(tree, flow->srcIP, output);
	updateEntry(output, ((uint64_t)(flow->flowStart / 300 / 1000)) * 300, flow->revBytes, flow->revPackets, flow->bytes, flow->packets);

	lpm_lookup(tree, flow->dstIP, output);
	updateEntry(output, ((uint64_t)(flow->flowStart / 300 / 1000)) * 300, flow->bytes, flow->packets, flow->revBytes, flow->revPackets);
}

void RRDVisAnalyzer::nextTable()
{
	// nexttable pushes all information to the RRDs
	// this is only done when a table is finished as we may only push 
	// newer data to rrdtool
	// we can only be sure to have no older data when we read a new table
	for (SubnetList::iterator i = subnetList.begin(); i != subnetList.end(); ++i) {
		std::cout << i->first << std::endl;
		for (TimeSubnetStats::iterator j = i->second.begin(); j != i->second.end(); ++j) {
			std::cout << "\t" << j->first << std::endl;
			std::cout << "\t\t" << j->second.in_bytes << std::endl;
			std::cout << "\t\t" << j->second.in_packets << std::endl;
			std::cout << "\t\t" << j->second.out_bytes << std::endl;
			std::cout << "\t\t" << j->second.out_packets << std::endl;

		}
	}
}


void RRDVisAnalyzer::passResults()
{
	nextTable();
}


void RRDVisAnalyzer::initDatabases()
{
	for (std::map<std::string, std::string>::iterator i = rrdDBMap.begin(); i != rrdDBMap.end(); ++i) {

	}
}
