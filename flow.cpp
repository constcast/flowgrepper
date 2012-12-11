#include "flow.h"

#include <stdlib.h>
#include <stdexcept>
#include <iostream>

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
	if (target == "sourceIPv4Address" || target == "SOURCEIPV4ADDRESS") {
		srcIP = atoi(value);
	} else if (target == "destinationIPv4Address" || target == "DESTINATIONIPV4ADDRESS") {
		dstIP = atoi(value);
	} else if (target == "sourceTransportPort" || target == "SOURCETRANSPORTPORT") {
		srcPort = atoi(value);
	} else if (target == "destinationTransportPort" || target == "DESTINATIONTRANSPORTPORT") {
		dstPort = atoi(value);
	} else if (target == "protocolIdentifier" || target == "PROTOCOLIDENTIFIER") {
		proto = atoi(value);
	} else if (target == "flowStartMilliSeconds" || target == "FLOWSTARTMILLISECONDS") {
		flowStart = atoll(value);
	} else if (target == "flowEndMilliSeconds" || target == "FLOWENDMILLISECONDS") {
		flowEnd = atoll(value);
	} else if (target == "octetDeltaCount" || target == "OCTETDELTACOUNT") {
		bytes = atoll(value);
	} else if (target == "packetDeltaCount" || target == "PACKETDELTACOUNT") {
		packets = atoll(value);
	} else if (target == "tcpControlBits" || target == "TCPCONTROLBITS") {
		// skip
	} else if (target == "revflowStartMilliSeconds" || target == "REVFLOWSTARTMILLISECONDS") {
		revFlowStart = atoll(value);
	} else if (target == "revflowEndMilliSeconds" || target == "REVFLOWENDMILLISECONDS") {
		revFlowEnd = atoll(value);
	} else if (target == "revoctetDeltaCount" || target == "REVOCTETDELTACOUNT") {
		revBytes = atoll(value);
	} else if (target == "revpacketDeltaCount" || target == "REVPACKETDELTACOUNT") {
		revPackets = atoll(value);
	} else if (target == "revtcpControlBits" || target == "REVTCPCONTROLBITS") {
		// skip
	} else {
		//std:: cerr << "Unknown field " + target + "!" << std::endl;
	}
}

