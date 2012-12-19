#include "rrdvis.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <sstream>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>

#include "flow.h"
#include "reporterbase.h"

#include <rrd.h>


RRDVisAnalyzer::RRDVisAnalyzer(const ConfigObject& configObject, ReporterBase& reporter)
	: AnalyzerBase(configObject, reporter), configSection("rrdvisualizer"), firstFlow(true), lastFlowStart(0)
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

			rrdDBMap[subnet_string] = token;

			lpm_insert(tree, ip.c_str(), atoi(mask.c_str()));
			
			subnet = true;
		}
	}

	// define the number of values that need to be aggregated
	// by the rrdtools
	intervals.push_back(1);
	intervals.push_back(5);
	intervals.push_back(30);
	intervals.push_back(120);
	intervals.push_back(24*60);

	// graph time spans
	graphTimeSpans.push_back("-1d");
	graphTimeSpans.push_back("-1w");
	graphTimeSpans.push_back("-1m");
	graphTimeSpans.push_back("-1y");
}

RRDVisAnalyzer::~RRDVisAnalyzer()
{
	lpm_destroy(tree);	
}

void RRDVisAnalyzer::updateEntry(const std::string &targetNet, uint64_t startTimestamp, uint64_t endTimestamp, uint8_t protocol, uint64_t inbytes, uint64_t inpackets, uint64_t outbytes, uint64_t outpackets)
{
	if (startTimestamp == 0) {
		// no traffic in this direction. do nothing
		return;
	}

	std::string subnet = targetNet;
	if (subnet == "NF") {
		subnet = "0.0.0.0/0";
	}
	if (subnetList.find(subnet) == subnetList.end()) {
		TimeSubnetStats s;
		subnetList[subnet] = s;
	}

	TimeSubnetStats& stats = subnetList[subnet];
	uint64_t intervalStart = (uint64_t)((uint64_t)(startTimestamp / 1000) / 60) * 60;
	uint64_t intervalEnd = (uint64_t)((uint64_t)(endTimestamp / 1000) / 60) * 60;
	if (intervalStart > lastFlowStart) {
		lastFlowStart = intervalStart;
	}

	// split flow counters to intervals
	float factor = (intervalEnd - intervalStart) / 60;
	if (intervalEnd == intervalStart) {
		factor = 1;
	} else if (intervalEnd < intervalStart) {
		throw std::runtime_error("Interval end is before interval start!");
	}
	//std::cout << intervalEnd << " " << intervalStart << " "<< factor << std::endl;

	float inbytes_factor = (float)(inbytes) / factor;
	float outbytes_factor = (float)(outbytes) / factor;
	float inpackets_factor = (float)(inpackets) / factor;
	float outpackets_factor = (float)(outpackets) / factor;
	for (uint64_t i = intervalStart; i <= intervalEnd; i+= 60) {
		if (stats.find(i) == stats.end()) {
			SubnetStats s;
			memset(&s, 0, sizeof(s));
			stats[i] = s;
		}

		SubnetStats& subnetStats = stats.find(i)->second;
		subnetStats.out_bytes   += outbytes_factor;
		subnetStats.in_bytes    += inbytes_factor;
		subnetStats.out_packets += outpackets_factor;
		subnetStats.in_packets  += inpackets_factor;

		switch (protocol) {
			case 6:
				subnetStats.out_tcp_bytes   += outbytes_factor;
				subnetStats.out_tcp_packets += outpackets_factor;
				subnetStats.in_tcp_bytes    += inbytes_factor;
				subnetStats.in_tcp_packets  += inpackets_factor;
				break; 
			case 17:
				subnetStats.out_udp_bytes   += outbytes_factor;
				subnetStats.out_udp_packets += outpackets_factor;
				subnetStats.in_udp_bytes    += inbytes_factor;
				subnetStats.in_udp_packets  += inpackets_factor;
				break;
			case 1:
				//std::cout << inbytes_factor << " " << outbytes_factor << " " << inbytes << " " << outbytes << std::endl;
				subnetStats.out_icmp_bytes   += outbytes_factor;
				subnetStats.out_icmp_packets += outpackets_factor;
				subnetStats.in_icmp_bytes    += inbytes_factor;
				subnetStats.in_icmp_packets  += inpackets_factor;
				break;
		};

	}
}

void RRDVisAnalyzer::analyzeFlow(const Flow* flow)
{
	if (firstFlow) {
		initDatabases((uint64_t)(((uint64_t)flow->flowStart / 1000) / 60) * 60);
		firstFlow = false;
	}
	static char output[16];
	lpm_lookup(tree, flow->srcIP, output);

	// VERMONT does not use the timestamps properly to determine which direction of the
	// flow did start the flow. It is therefore possible that the reverse flow direction
	// actually started the flow. Hence, we need to check this manually. 
	if (flow->flowStart < flow->revFlowStart) {
		updateEntry(output, flow->flowStart, flow->flowEnd, flow->proto, flow->revBytes, flow->revPackets, flow->bytes, flow->packets);
	} else {
		updateEntry(output, flow->revFlowStart, flow->revFlowEnd, flow->proto, flow->bytes, flow->packets, flow->revBytes, flow->revPackets);
	}

	lpm_lookup(tree, flow->dstIP, output);
	if (flow->flowStart < flow->revFlowStart) {
		updateEntry(output, flow->revFlowStart, flow->revFlowEnd, flow->proto, flow->bytes, flow->packets, flow->revBytes, flow->revPackets);
	} else {
		updateEntry(output, flow->flowStart, flow->flowEnd, flow->proto, flow->revBytes, flow->revPackets, flow->bytes, flow->packets);
	}
}

void RRDVisAnalyzer::graphRRD(const std::string& graph_file, const std::string& rrd_db, const std::string& title, const std::string& type, const std::string&  start)
{
	const size_t length = 350;
	const size_t array_length = 50;
	char* rrd_args[array_length];
	for (size_t i = 0; i != array_length; ++i) {
		rrd_args[i] = (char*) malloc(length*sizeof(char));	
		bzero(rrd_args[i], length);
	}

	size_t rrdIndexCounter = 0;
	int       xsize, ysize;
	double    ymin, ymax;
	char    **calcpr;
	std::stringstream args_stream;
	std::string arg;

	strncpy(rrd_args[rrdIndexCounter++], "graph", length);

	strncpy(rrd_args[rrdIndexCounter++], graph_file.c_str(), graph_file.length()>length?length:graph_file.length());
	if (type == "bytes") {
		arg = "DEF:in_bytes=" + rrd_db + ":in_bytes:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:in_tcp_bytes=" + rrd_db + ":in_tcp_bytes:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:in_udp_bytes=" + rrd_db + ":in_udp_bytes:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:in_icmp_bytes=" + rrd_db + ":in_icmp_bytes:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);

		arg ="DEF:out_bytes=" + rrd_db + ":out_bytes:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:out_tcp_bytes=" + rrd_db + ":out_tcp_bytes:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:out_udp_bytes=" + rrd_db + ":out_udp_bytes:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:out_icmp_bytes=" + rrd_db + ":out_icmp_bytes:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);


		strncpy(rrd_args[rrdIndexCounter++], "AREA:in_tcp_bytes#f00000:IN_TCP_BYTES:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "AREA:in_udp_bytes#f0f000:IN_UDP_BYTES:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "AREA:in_icmp_bytes#f00ff0:IN_ICMP_BYTES:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "LINE1:in_bytes#000000:IN_BYTES", length);

		strncpy(rrd_args[rrdIndexCounter++], "AREA:out_tcp_bytes#f00000:OUT_TCP_BYTES", length);
		strncpy(rrd_args[rrdIndexCounter++], "AREA:out_udp_bytes#f0f000:OUT_UDP_BYTES:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "AREA:out_icmp_bytes#f00ff0:OUT_ICMP_BYTES:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "LINE1:out_bytes#0000ff:OUT_BYTES", length);

		strncpy(rrd_args[rrdIndexCounter++], "HRULE:0#000000:Zero Line", length);
	} else  if (type == "packets") {
		arg = "DEF:in_packets=" + rrd_db + ":in_packets:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:in_tcp_packets=" + rrd_db + ":in_tcp_packets:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:in_udp_packets=" + rrd_db + ":in_udp_packets:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:in_icmp_packets=" + rrd_db + ":in_icmp_packets:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);

		arg ="DEF:out_packets=" + rrd_db + ":out_packets:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:out_tcp_packets=" + rrd_db + ":out_tcp_packets:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:out_udp_packets=" + rrd_db + ":out_udp_packets:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);
		arg = "DEF:out_icmp_packets=" + rrd_db + ":out_icmp_packets:AVERAGE";
		strncpy(rrd_args[rrdIndexCounter++], arg.c_str(), length);


		strncpy(rrd_args[rrdIndexCounter++], "AREA:in_tcp_packets#f00000:IN_TCP_PACKETS:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "AREA:in_udp_packets#f0f000:IN_UDP_PACKETS:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "AREA:in_icmp_packets#f00ff0:IN_ICMP_PACKETS:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "LINE1:in_packets#000000:IN_PACKETS", length);

		strncpy(rrd_args[rrdIndexCounter++], "AREA:out_tcp_packets#f00000:OUT_TCP_PACKETS", length);
		strncpy(rrd_args[rrdIndexCounter++], "AREA:out_udp_packets#f0f000:OUT_UDP_PACKETS:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "AREA:out_icmp_packets#f00ff0:OUT_ICMP_PACKETS:STACK", length);
		strncpy(rrd_args[rrdIndexCounter++], "LINE1:out_packets#ffff00:OUT_PACKETS", length);
	}

	args_stream <<  lastFlowStart << start;
	strncpy(rrd_args[rrdIndexCounter++], "--start", length);
	strncpy(rrd_args[rrdIndexCounter++], args_stream.str().c_str(), length);

	strncpy(rrd_args[rrdIndexCounter++], "--title", length);
	args_stream.str("");
	args_stream << lastFlowStart;
	strncpy(rrd_args[rrdIndexCounter++], args_stream.str().c_str(), length);


	strncpy(rrd_args[rrdIndexCounter++], "--end", length);
	args_stream.str("");
	args_stream << lastFlowStart;
	strncpy(rrd_args[rrdIndexCounter++], args_stream.str().c_str(), length);

	strncpy(rrd_args[rrdIndexCounter++], "--width", length);
	args_stream.str("");
	args_stream << 1024;
	strncpy(rrd_args[rrdIndexCounter++], args_stream.str().c_str(), length);

	strncpy(rrd_args[rrdIndexCounter++], "--height", length);
	args_stream.str("");
	args_stream << 860;
	strncpy(rrd_args[rrdIndexCounter++], args_stream.str().c_str(), length);

	strncpy(rrd_args[rrdIndexCounter++], "--slope-mode", length);

	rrd_args[rrdIndexCounter] = NULL;
	if (rrd_graph(rrdIndexCounter, (char**)rrd_args, &calcpr, &xsize, &ysize, NULL, &ymin, &ymax) != 0) {
		std::cout << "Failed to graph: " << rrd_get_error() << std::endl;
		rrd_clear_error();
	} else {
		if (calcpr) {
			for (size_t i = 0; calcpr[i]; i++) {
				free(calcpr[i]);
			}
			free(calcpr);
		}
	}

	for (size_t i = 0; i != array_length; ++i) {
		free(rrd_args[i]);
	}


}

void RRDVisAnalyzer::nextTable()
{
	// nexttable pushes all information to the RRDs
	// this is only done when a table is finished as we may only push 
	// newer data to rrdtool
	// we can only be sure to have no older data when we read a new table
	std::cout << "Starting to update rrds ..." << std::endl;

	// this char** is necessary for the rrd_* calls. 
	// we only need 4 strings for the rrd_update calls.
	// later on we need to include more for the graphing parts (hence array_length = 30)
	const size_t length = 350;
	const size_t array_length = 30;
	char* rrd_args[array_length];
	for (size_t i = 0; i != 3; ++i) {
		rrd_args[i] = (char*) malloc(length*sizeof(char));	
		bzero(rrd_args[i], length);
	}
	rrd_args[4] = NULL;

	for (SubnetList::iterator i = subnetList.begin(); i != subnetList.end(); ++i) {
		std::cout  << "Writing " << i->first << " ..." << std::endl;
		for (TimeSubnetStats::iterator j = i->second.begin(); j != i->second.end(); ++j) {
			/*
			std::stringstream command;
			command << rrdPath << " update " << rrdDbPath << "/" << rrdDBMap[i->first] << " ";
			command << j->first << ":" << j->second.in_packets << ":" << j->second.in_bytes << ":";
			command << j->second.out_packets << ":" << j->second.out_bytes << ":";
			command << j->second.out_packets + j->second.in_packets << ":" << j->second.out_bytes + j->second.in_bytes;
			std::cout << command.str() << std::endl;
			system(command.str().c_str());
			*/
			std::stringstream update;
			update << j->first << ":" ;
			update << (int64_t)0-(int64_t)(j->second.in_packets) << ":" <<  (int64_t)0-(int64_t)(j->second.in_tcp_packets) << ":" << (int64_t)0-(int64_t)(j->second.in_udp_packets) << ":" << (int64_t)0-(int64_t)(j->second.in_icmp_packets) << ":";

			update << (int64_t)0-(int64_t)(j->second.in_bytes) << ":" << (int64_t)0-(int64_t)(j->second.in_tcp_bytes) << ":" << (int64_t)0-(int64_t)(j->second.in_udp_bytes) << ":" << (int64_t)0-(int64_t)(j->second.in_icmp_bytes) << ":";

			update << j->second.out_packets << ":" << j->second.out_tcp_packets << ":" << j->second.out_udp_packets << ":" << j->second.out_icmp_packets << ":";
			update << j->second.out_bytes << ":" <<  j->second.out_tcp_bytes << ":" << j->second.out_udp_bytes << ":" << j->second.out_icmp_bytes << ":";

			update << j->second.out_packets + j->second.in_packets << ":" 
				<< j->second.out_tcp_packets + j->second.in_tcp_packets << ":" 
				<< j->second.out_udp_packets + j->second.in_udp_packets << ":"
				<< j->second.out_icmp_packets + j->second.in_icmp_packets << ":";

			update << j->second.out_bytes + j->second.in_bytes << ":"
				<< j->second.out_tcp_bytes + j->second.in_tcp_bytes << ":"
				<< j->second.out_udp_bytes + j->second.in_udp_bytes << ":"
				<< j->second.out_icmp_bytes + j->second.in_icmp_bytes;

			strncpy(rrd_args[0], "update", length);
			strncpy(rrd_args[1], (rrdDbPath +"/" +  rrdDBMap[i->first]).c_str(), length);
			strncpy(rrd_args[2], update.str().c_str(), length);
			//std:: cout << rrd_args[0] << " " << rrd_args[1] << " " << rrd_args[2] << " " << rrd_args[3] << std::endl;;
			if (rrd_update(3, (char**)rrd_args) != 0) {
				std::cout << "Failed to update rrdtool: " << rrd_get_error() << std::endl;
				rrd_clear_error();
			}
		}
	}
	for (size_t i = 0; i != 3; ++i) {
		free(rrd_args[i]);
	}

	std::cout << "Updated rrds ..." << std::endl;

	std::cout << "Generating graphs ..." << std::endl;

	// allocate char arrays;
	for (size_t i = 0; i != array_length; ++i) {
		rrd_args[i] = (char*) malloc(length*sizeof(char));	
		bzero(rrd_args[i], length);
	}


	for (SubnetList::iterator i = subnetList.begin(); i != subnetList.end(); ++i) {

		std::string rrd_db = rrdDbPath +"/" +  rrdDBMap[i->first];

		for (size_t j = 0; j != graphTimeSpans.size(); ++j) {
			std::string graph_file = rrdDbPath + "/" + rrdDBMap[i->first] + "-bytes" + graphTimeSpans[j] + ".png";
			if (graph_file.size() > length) {
				throw std::runtime_error("Error: graph_file.size() > length");
			}
			graphRRD(graph_file, rrd_db, rrdDBMap[i->first], "bytes", graphTimeSpans[j]);

			graph_file = rrdDbPath + "/" + rrdDBMap[i->first] + "-packets" + graphTimeSpans[j] + ".png";
			graphRRD(graph_file, rrd_db, rrdDBMap[i->first], "packets", graphTimeSpans[j]);

		}
	}

	subnetList.clear();
}


void RRDVisAnalyzer::passResults()
{
	nextTable();
}


void RRDVisAnalyzer::initDatabases(uint64_t start)
{
	for (std::map<std::string, std::string>::iterator i = rrdDBMap.begin(); i != rrdDBMap.end(); ++i) {
		// check if the rrd exists.
		struct stat fbuf;
		std::stringstream command;
		command << rrdDbPath << "/" << i->second;
		std::string rrdFilename = command.str();
		command.str("");
		if (stat(rrdFilename.c_str(), &fbuf) == 0) {
			std::cout << "A file named " << rrdFilename << " already exists!" << std::endl;
			std::cout << "Not creating new rrd database ..." << std::endl;
			continue;
		}


		command << rrdPath << " create " << rrdFilename << " --start " << start - 60 << " --step=60 ";
		// add datasources 
		command << "DS:in_packets:ABSOLUTE:60:U:U ";
		command << "DS:in_tcp_packets:ABSOLUTE:60:U:U ";
		command << "DS:in_udp_packets:ABSOLUTE:60:U:U ";
		command << "DS:in_icmp_packets:ABSOLUTE:60:U:U ";

		command << "DS:in_bytes:ABSOLUTE:60:U:U ";
		command << "DS:in_tcp_bytes:ABSOLUTE:60:U:U ";
		command << "DS:in_udp_bytes:ABSOLUTE:60:U:U ";
		command << "DS:in_icmp_bytes:ABSOLUTE:60:U:U ";

		command << "DS:out_packets:ABSOLUTE:60:U:U ";
		command << "DS:out_tcp_packets:ABSOLUTE:60:U:U ";
		command << "DS:out_udp_packets:ABSOLUTE:60:U:U ";
		command << "DS:out_icmp_packets:ABSOLUTE:60:U:U ";

		command << "DS:out_bytes:ABSOLUTE:60:U:U ";
		command << "DS:out_tcp_bytes:ABSOLUTE:60:U:U ";
		command << "DS:out_udp_bytes:ABSOLUTE:60:U:U ";
		command << "DS:out_icmp_bytes:ABSOLUTE:60:U:U ";

		command << "DS:total_packets:ABSOLUTE:60:U:U ";
		command << "DS:total_tcp_packets:ABSOLUTE:60:U:U ";
		command << "DS:total_udp_packets:ABSOLUTE:60:U:U ";
		command << "DS:total_icmp_packets:ABSOLUTE:60:U:U ";

		command << "DS:total_bytes:ABSOLUTE:60:U:U ";
		command << "DS:total_tcp_bytes:ABSOLUTE:60:U:U ";
		command << "DS:total_udp_bytes:ABSOLUTE:60:U:U ";
		command << "DS:total_icmp_bytes:ABSOLUTE:60:U:U ";

		for (size_t j = 0; j != intervals.size(); ++j) {
			command << "RRA:AVERAGE:0.5:" << intervals[j] << ":600 ";
		}
		std::cout << command.str() << std::endl;
		system(command.str().c_str());
	}
}
