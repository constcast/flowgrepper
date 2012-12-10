#include "flow.h"

#include <stdlib.h>
#include <stdexcept>

Flow::Flow(uint32_t srcIP, uint32_t dstIP, uint16_t srcPort, uint16_t dstPort, uint8_t proto, uint64_t flowStart, uint64_t flowEnd, uint64_t packets, uint64_t bytes, uint64_t revFlowStart, uint64_t revFlowEnd, uint64_t revPackets, uint64_t revBytes)
	: srcIP(srcIP), dstIP(dstIP), srcPort(srcPort), dstPort(dstPort), proto(proto), flowStart(flowStart), flowEnd(flowEnd), packets(packets), bytes(bytes), revFlowStart(revFlowStart), revFlowEnd(revFlowEnd), revPackets(revPackets), revBytes(revBytes)
{

}

Flow::Flow()
	: srcIP(0), dstIP(0), srcPort(0), dstPort(0), proto(0), flowStart(0), flowEnd(0), packets(0), bytes(0), revFlowStart(0), revFlowEnd(0), revPackets(0), revBytes(0)
{

}

void Flow::setValue(const std::string& target, const char* value)
{
	if (target == "sourceIPv4Address") {
		srcIP = atoi(value);
	} else if (target == "destinationIPv4Address") {
		dstIP = atoi(value);
	} else if (target == "sourceTransportPort") {
		srcPort = atoi(value);
	} else if (target == "destinationTransportPort") {
		dstPort = atoi(value);
	} else if (target == "protocolIdentifier") {
		proto = atoi(value);
	} else if (target == "flowStartMilliSeconds") {
		flowStart = atoll(value);
	} else if (target == "flowEndMilliSeconds") {
		flowEnd = atoll(value);
	} else if (target == "octetDeltaCount") {
		bytes = atoll(value);
	} else if (target == "packetDeltaCount") {
		packets = atoll(value);
	} else if (target == "tcpControlBits") {
		// skip
	} else if (target == "revflowStartMilliSeconds") {
		revFlowStart = atoll(value);
	} else if (target == "revflowEndMilliSeconds") {
		revFlowEnd = atoll(value);
	} else if (target == "revoctetDeltaCount") {
		revBytes = atoll(value);
	} else if (target == "revpacketDeltaCount") {
		revPackets = atoll(value);
	} else if (target == "revtcpControlBits") {
		// skip
	} else {
		throw std::runtime_error("Unknown field " + target + "!");
	}
}

