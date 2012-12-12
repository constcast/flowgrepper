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

	while (subnetConfig) {
		subnetConfig >> token;
		if (subnet) {
			subnet_string = token;
			subnet = false;
		} else {
			//subnetMap[subnet_string] = token;
			size_t pos = subnet_string.find("/");
			if (pos == std::string::npos) {
				throw std::runtime_error("Error: Cannot parse subnet \"" + subnet_string + "\"");
			}
			std::string ip   = subnet_string.substr(0, pos);
			std::string mask = subnet_string.substr(pos + 1, subnet_string.size());

			lpm_insert(tree, ip.c_str(), atoi(mask.c_str()));
			subnet = true;
		}
	}
}

RRDVisAnalyzer::~RRDVisAnalyzer()
{
	lpm_destroy(tree);	
}

void RRDVisAnalyzer::analyzeFlow(const Flow* flow)
{
	static char output[16];
	lpm_lookup(tree, flow->srcIP, output);
//	std::cout << flow->srcIP << " <-> " << output << std::endl;
//	std::cout << flow->srcIP
}

void RRDVisAnalyzer::nextTable()
{
	// nexttable pushes all information to the RRDs
	// this is only done when a table is finished as we may only push 
	// newer data to rrdtool
	// we can only be sure to have no older data when we read a new table

}


void RRDVisAnalyzer::passResults()
{
	nextTable();
}

