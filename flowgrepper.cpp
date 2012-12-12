#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <iterator>
#include <algorithm>
#include <map>
#include <stdexcept>
#include <vector>

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <vector>

#include "flowdb.h"
#include "flow.h"
#include "configobject.h"

#include "onewayflowanalyzer.h"
#include "rrdvis.h"

#include "reporterprinter.h"

AnalyzerBase* createAnalyzer(const std::string& name, const ConfigObject& configObject,  ReporterBase& reporter)
{
	if (name == "onewayflowanalyzer") {
		return new OneWayFlowAnalyzer(configObject, reporter);
	} else if (name == "rrdvisualizer") {
		return new RRDVisAnalyzer(configObject, reporter);
	} else {
		throw std::runtime_error("Error in createAnalyzer: Unknown analyzer module \"" + name + "\"!");
	}

	// we should never get here. this is just to make the compiler happy
	return NULL;
}

void usage(const std::string filename)
{
	std::cerr << "Usage: " << filename << "-f file [tablename, tablename ...]" << std::endl;
}

int main(int argc, char** argv)
{
	std::string config_file;
	std::vector<std::string> tableNames;
	int c;
        /* parse command line */
        while ((c=getopt(argc, argv, "hf:d")) != -1) {

                switch (c) {

                case 'f':
                        config_file=optarg;
                        break;
                case 'h':
                default:
                        /* print usage and quit vermont, if unknow switch */
                        usage(argv[0]);
                        return -1;
                }
        }

        if (config_file == "") {
                std::cerr << "Config file is mandatory!" << std::endl;
                usage(argv[0]);
                return -1;
        }

	ConfigObject confObject(config_file);
	for (int index = optind; index < argc; ++index) {
		tableNames.push_back(argv[index]);
	}

	std::string dbtype, hostIP, username, password, databaseName;
	uint16_t hostPort;

	dbtype       = confObject.getConfString("main", "dbtype");
	hostIP       = confObject.getConfString("main", "host");
	hostPort     = atoi(confObject.getConfString("main", "port").c_str());
	username     = confObject.getConfString("main", "username");
	password     = confObject.getConfString("main", "password");
	databaseName = confObject.getConfString("main", "database");

	// read and initialize modules
	std::string moduleString = confObject.getConfString("main", "modules");

	std::istringstream iss(moduleString);
	std::vector<std::string> modules;
	std::copy(std::istream_iterator<std::string>(iss),
			std::istream_iterator<std::string>(),
			std::back_inserter<std::vector<std::string> >(modules));

	ReporterBase* reporter = new ReporterPrinter();
	std::vector<AnalyzerBase*> analyzers;
	for (size_t i = 0; i != modules.size(); ++i) {
		analyzers.push_back(createAnalyzer(modules[i], confObject, *reporter));
	}

	FlowDBBase* flowdb = createFlowDB(dbtype, hostIP, hostPort, username, password);

	flowdb->connect(databaseName);
	flowdb->getTableNames();
	if (tableNames.size() > 0) {
		std::cout << "Filtering Tables ..." << std::endl;
		flowdb->limitTableSpace(tableNames);
	} else {
		std::cout << "Analyzing all tables ..." << std::endl;
	}

	Flow* flow;
	size_t counter = 0;
	while ((flow = flowdb->getNextFlow())) {
		if (counter == 0) {
			std::cout << "Received first flow from db ..." << std::endl;
		}
		for (size_t i = 0; i != analyzers.size(); ++i) {
			if (flow->firstOfNewTable) {
				analyzers[i]->nextTable();
			}
			analyzers[i]->analyzeFlow(flow);
		}
		delete flow;
		counter++;
		if (counter % 100000 == 0) {
			std::cout << "Analyzed " << counter << " flows ..." << std::endl;
		}
	}
	std::cout << "Finished reading flows from db! Reporting!" << std::endl;
	for (size_t i = 0; i != analyzers.size(); ++i) {
		analyzers[i]->passResults();
		delete analyzers[i];
	}

	delete reporter;
	delete flowdb;

	return 0;
}
