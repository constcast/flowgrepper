#ifndef _FLOWGREPPER_FLOW_H_
#define _FLOWGREPPER_FLOW_H_

#include <stdint.h>
#include <string>

class Flow 
{
public:
	Flow(uint32_t srcIP, uint32_t dstIP, uint16_t srcPort, uint16_t dstPort, uint8_t proto, uint64_t flowStart, uint64_t flowEnd, uint64_t packets, uint64_t bytes, uint64_t revFlowStart, uint64_t revFlowEnd, uint64_t revPackets, uint64_t revBytes);
	Flow();

	void setValue(const std::string& target, const char* value);

	uint32_t srcIP; 
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
	uint64_t revBytes;
};

#endif
