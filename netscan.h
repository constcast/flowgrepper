#ifndef _FLOWGREPPER_NETSCAN_ANALYZER_H_
#define _FLOWGREPPER_NETSCAN_ANALYZER_H_

#include "analyzerbase.h"

#include <tr1/tuple>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>
#include "flow.h"


class NetscanAnalyzer : public AnalyzerBase
{
public:
	NetscanAnalyzer(const ConfigObject& configObject, ReporterBase& reporter);

	virtual void analyzeFlow(const Flow* flow);
	virtual	void passResults();
	std::string convertIP(uint32_t);

private:
	const std::string configSection;
	
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int> data;
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, std::map<uint32_t, uint32_t> > data_list;
	std::map<std::pair<uint32_t, std::pair<uint32_t, uint16_t> >, int> data_norev;
	long current_bucket;
	long first_bucket;
	long start_time;
	unsigned int first_flow;
	float interval;
	int min_scans;
};

#endif
