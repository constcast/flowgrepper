#ifndef _FLOWGREPPER_DNSBL_ANALYZER_H_
#define _FLOWGREPPER_DNSBL_ANALYZER_H_

#include "analyzerbase.h"
#include "blacklist.h"

#include <map>
#include <stdint.h>
#include <string>
#include <vector>

#define MAX_IP_ENTRIES	550000

class DNSblAnalyzer : public AnalyzerBase
{
public:
	DNSblAnalyzer(const ConfigObject& configObject, ReporterBase& reporter);

	unsigned char* ReadFile(char* path);
	
	virtual void analyzeFlow(const Flow* flow);
	virtual	void passResults();

/*	struct blacklist {
		char* listname;
		unsigned char* list;
	};

*/	/*struct FlowCounters {
		uint64_t biflows;
		uint64_t oneWayTarget;
		uint64_t oneWaySource;
	}; */

	struct blackinfo {
		std::string listname;
		unsigned int count;
	};

private:
	std::map<unsigned int, blackinfo> finding;
	std::vector<Blacklist> blacklist;
	const std::string configSection;
};

#endif
