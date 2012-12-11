#include <iostream>
#include <string>
#include <fstream>

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <vector>

#include "flowdb.h"
#include "flow.h"

#include "onewayflowanalyzer.h"

#include "reporterprinter.h"

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

	for (int index = optind; index < argc; ++index) {
		tableNames.push_back(argv[index]);
	}

	// parse config
	std::ifstream configStream;
	configStream.open(config_file.c_str());
	/* expected format: 
		<dbtype>
		<host-ip>
		<host-port>
		<username>
		<password>
	*/
	std::string  line;
	std::string dbtype, hostIP, username, password, databaseName;
	uint16_t hostPort;

	if (!std::getline(configStream, line)) {
		std::cerr << "could not read dbtype from " << config_file << std::endl;
		return -1;
	}
	dbtype = line;

	if (!std::getline(configStream, line)) {
		std::cerr << "could not read host from " << config_file << std::endl;
		return -1;
	}
	hostIP = line;

	if (!std::getline(configStream, line)) {
		std::cerr << "could not read port from " << config_file << std::endl;
		return -1;
	}
	hostPort = atoi(line.c_str());
	
	if (!std::getline(configStream, line)) {
		std::cerr << "could not read username from " << config_file << std::endl;
		return -1;
	}
	username = line;

	if (!std::getline(configStream, line)) {
		std::cerr << "could not read password from " << config_file << std::endl;
		return -1;
	}
	password = line;

	if (!std::getline(configStream, line)) {
		std::cerr << "could not read database name from " << config_file << std::endl;
		return -1;
	}
	databaseName = line;


	FlowDBBase* flowdb = createFlowDB(dbtype, hostIP, hostPort, username, password);

	ReporterBase* reporter = new ReporterPrinter();
	OneWayFlowAnalyzer* oneway = new OneWayFlowAnalyzer(reporter);

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
		oneway->analyzeFlow(flow);
		delete flow;
		counter++;
		if (counter % 100000 == 0) {
			std::cout << "Analyzed " << counter << " flows ..." << std::endl;
		}
	}
	std::cout << "Finished reading flows from db! Reporting!" << std::endl;
	oneway->passResults();


	delete oneway;
	delete reporter;
	delete flowdb;

	return 0;
}
