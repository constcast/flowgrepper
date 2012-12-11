#include "onewayflowanalyzer.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sstream>

#include "flow.h"
#include "reporterbase.h"


OneWayFlowAnalyzer::OneWayFlowAnalyzer(ReporterBase* reporter)
	: AnalyzerBase(reporter)
{

}
	
void OneWayFlowAnalyzer::analyzeFlow(const Flow* flow)
{
	// handle srcIP
	if (counters.find(flow->srcIP) == counters.end()) {
		// did not yet see srcIP
		FlowCounters c;
		memset(&c, 0, sizeof(FlowCounters));
		counters[flow->srcIP] = c;
	}
	FlowCounters* srcCounters = &counters[flow->srcIP];
	if (flow->revPackets > 0) {
		srcCounters->biflows++;
	} else {
		srcCounters->oneWaySource++;
	}

	// handle dstIP
	if (counters.find(flow->dstIP) == counters.end()) {
		FlowCounters c;
		memset(&c, 0, sizeof(FlowCounters));
		counters[flow->dstIP] = c;
	}
	FlowCounters* dstCounters = &counters[flow->dstIP];
	if (flow->revPackets > 0) {
		dstCounters->biflows++;
	} else {
		dstCounters->oneWayTarget++;
	}

	//uint32_t smaller = flow->srcIP<flow->dstIP?flow->srcIP:flow->dstIP;
	//uint32_t bigger = flow->srcIP>flow->dstIP?flow->dstIP:flow->srcIP;
	//uint64_t pair 2
}


void OneWayFlowAnalyzer::passResults()
{

	for (std::map<uint32_t, FlowCounters>::iterator i = counters.begin(); i != counters.end(); ++i) {
		std::stringstream sstream;
		struct in_addr addr;
		addr.s_addr = htonl(i->first);
		sstream << "IP:\t" << i->first << "\t" << inet_ntoa(addr) << "\t\t" << i->second.biflows << "\t" << i->second.oneWayTarget << "\t" << i->second.oneWaySource;
		reporter->addLogString(sstream.str());
	}
}

