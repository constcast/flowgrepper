#ifndef _FLOWGREPPER_RRD_VIS_H_
#define _FLOWGREPPER_RRD_VIS_H_

#include "analyzerbase.h"

#include <map>
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
		uint64_t in_packets;
		uint64_t out_bytes;
		uint64_t out_packets;
	};

	typedef std::map<uint64_t , SubnetStats> TimeSubnetStats;
	typedef std::map<std::string, TimeSubnetStats> SubnetList;

private:
	std::string configFile;
	std::string rrdPath;
	std::string rrdDbPath;

	SubnetList subnetList;

	std::map<std::string, std::string> rrdDBMap;

	const std::string configSection;
	struct lpm_tree* tree;

	void updateEntry(const std::string &subnet, uint64_t timestamp, uint64_t inbytes, uint64_t inpackets, uint64_t outbytes, uint64_t outpackets);
	void initDatabases();
};

#endif
