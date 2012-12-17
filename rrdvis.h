#ifndef _FLOWGREPPER_RRD_VIS_H_
#define _FLOWGREPPER_RRD_VIS_H_

#include "analyzerbase.h"

#include <map>
#include <vector>
#include <stdint.h>
#include <string>
extern "C" {
#include "longest-prefix/tree.h"
}


class RRDVisAnalyzer : public AnalyzerBase
{
public:
	RRDVisAnalyzer(const ConfigObject& configObject, ReporterBase& reporter);
	~RRDVisAnalyzer();
	
	virtual void analyzeFlow(const Flow* flow);
	virtual	void passResults();
	virtual void nextTable();

	struct SubnetStats {
		uint64_t in_bytes;
		uint64_t in_tcp_bytes;
		uint64_t in_udp_bytes;
		uint64_t in_icmp_bytes;

		uint64_t in_packets;
		uint64_t in_tcp_packets;
		uint64_t in_udp_packets;
		uint64_t in_icmp_packets;

		uint64_t out_bytes;
		uint64_t out_tcp_bytes;
		uint64_t out_udp_bytes;
		uint64_t out_icmp_bytes;

		uint64_t out_packets;
		uint64_t out_tcp_packets;
		uint64_t out_udp_packets;
		uint64_t out_icmp_packets;
	};

	typedef std::map<uint64_t , SubnetStats> TimeSubnetStats;
	typedef std::map<std::string, TimeSubnetStats > SubnetList;

private:
	std::string configFile;
	std::string rrdPath;
	std::string rrdDbPath;

	SubnetList subnetList;

	std::map<std::string, std::string> rrdDBMap;
	std::vector<uint32_t> intervals;

	std::vector<std::string> graphTimeSpans;

	const std::string configSection;
	struct lpm_tree* tree;

	bool firstFlow;
	uint64_t lastFlowStart;

	void updateEntry(const std::string &subnet, uint64_t startTimestamp, uint64_t endTimestamp, uint8_t protocol, uint64_t inbytes, uint64_t inpackets, uint64_t outbytes, uint64_t outpackets);
	void initDatabases(uint64_t start);

	void graphRRD(const std::string& graph_file, const std::string& rrd_db, const std::string& title, const std::string& type, const std::string& start);
};

#endif
