#ifndef _FLOWGREPPER_DNSBL_ANALYZER_H_
#define _FLOWGREPPER_DNSBL_ANALYZER_H_

#include "analyzerbase.h"
#include "blacklist.h"

#include <map>
#include <stdint.h>
#include <string>
#include <vector>
#include "flow.h"


class DNSblAnalyzer : public AnalyzerBase
{
public:
	DNSblAnalyzer(const ConfigObject& configObject, ReporterBase& reporter);

	unsigned char* ReadFile(char* path);
	void InsertFinding(std::vector<Blacklist>::iterator, uint32_t, const Flow*);
	void InsertPort(uint16_t, uint8_t);
	virtual void analyzeFlow(const Flow* flow);
	virtual	void passResults();


	struct blackinfo {
		std::string listname;
		unsigned int count;

	};

	struct Dataset{
		uint32_t ip;
		uint32_t blackip;
	/*	uint32_t srcIP; 
		uint32_t dstIP; 
		uint16_t srcPort; 
		uint16_t dstPort; 
		uint8_t proto; 
		uint64_t flowStart; 
		uint64_t flowEnd; 
		uint64_t packets; 
		uint64_t bytes; 
		uint64_t revFlowStart; 
		uint64_t revFlowEnd; 
		uint64_t revPackets; 
		uint64_t revBytes; */
		int direction;
		Flow fl;
		std::string blacklist_name;
	};

private:
	std::map<unsigned int, blackinfo> finding;
	std::vector<Dataset> dataset;
	//std::map<uint32_t, unsigned int> ports_tcp;
	//std::map<uint32_t, unsigned int> ports_udp;

	std::vector<Blacklist> blacklist;
	const std::string configSection;
	unsigned int c;
	unsigned int fl_count;
};

#endif
