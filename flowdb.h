#ifndef _FLOWGREPPER_FLOW_DB_H_
#define _FLOWGREPPER_FLOW_DB_H_

#include <string>
#include <stdint.h>

class Flow;

class FlowDBBase 
{
public:
	FlowDBBase(const std::string& host, const uint16_t port, const std::string& username, const std::string& password);

	virtual Flow* getNextFlow() = 0;
	virtual void connect(const std::string& database_name) = 0;

protected:
	std::string host;
	uint16_t port;
	std::string username;
	std::string password;
	
};


FlowDBBase* createFlowDB(const std::string& type, const std::string& host, const uint16_t port, const std::string& username, const std::string& password);

#endif
