#ifndef _FLOWGREPPER_FAN_ANALYZER_H_
#define _FLOWGREPPER_FAN_ANALYZER_H_

#include "analyzerbase.h"

#include <map>
#include <stdint.h>
#include <string>
#include <vector>
#include "flow.h"


class FanAnalyzer : public AnalyzerBase
{
public:
	FanAnalyzer(const ConfigObject& configObject, ReporterBase& reporter);

	virtual void analyzeFlow(const Flow* flow);
	virtual	void passResults();
	std::string convertIP(uint32_t);

private:
	struct info{
		uint32_t bytes;
		uint32_t packets;
		uint32_t revbytes;
		uint32_t revpackets;
		uint32_t flows;
	};
	const std::string configSection;
	
	std::map<std::pair<uint32_t, uint32_t>, struct info> data_out;
	std::map<std::pair<uint32_t, uint32_t>, uint32_t> data_in;

	long current_bucket;
	long first_bucket;
	long start_time;
	unsigned int first_flow;
	float interval;
	uint32_t min_fanout;
	uint32_t min_fanin;
	uint32_t protocol;


};

#endif
