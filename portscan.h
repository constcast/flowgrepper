#ifndef _FLOWGREPPER_PORTSCAN_ANALYZER_H_
#define _FLOWGREPPER_PORTSCAN_ANALYZER_H_

#include "analyzerbase.h"

#include <tr1/tuple>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>
#include "flow.h"


class PortscanAnalyzer : public AnalyzerBase
{
public:
	PortscanAnalyzer(const ConfigObject& configObject, ReporterBase& reporter);

	virtual void analyzeFlow(const Flow* flow);
	virtual	void passResults();
	std::string convertIP(uint32_t);

private:
	const std::string configSection;
	
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint32_t> >, int> data;
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint32_t> >, std::map<uint16_t, uint32_t> > data_list;
	
	std::map<std::pair<uint32_t, std::pair<uint16_t, std::pair<uint32_t, uint32_t> > >, std::map<uint16_t, uint32_t> > data_extended;
	//std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int> data_norev;
	long current_bucket;
	long first_bucket;
	long start_time;
	unsigned int first_flow;
	float interval;
	int min_scans; 
	int extended;
	unsigned int highport;
	unsigned int max_out_packets;
	unsigned int protocol;
};

#endif
