#ifndef _FLOWGREPPER_ONE_WAY_FLOW_ANALYZER_H_
#define _FLOWGREPPER_ONE_WAY_FLOW_ANALYZER_H_

#include "analyzerbase.h"

#include <map>
#include <stdint.h>

class OneWayFlowAnalyzer : public AnalyzerBase
{
public:
	OneWayFlowAnalyzer(ReporterBase* reporter);
	
	virtual void analyzeFlow(const Flow* flow);
	virtual	void passResults();

	struct FlowCounters {
		uint64_t biflows;
		uint64_t oneWayTarget;
		uint64_t oneWaySource;
	};

private:
	std::map<uint32_t, FlowCounters> counters;
	std::map<uint64_t, uint32_t> unsucessfulPairs;
};

#endif
