#ifndef _FLOWGREPPER_FLOW_DB_H_
#define _FLOWGREPPER_FLOW_DB_H_

#include <string>
#include <stdint.h>
#include <vector>

#include "flow.h"

class FlowDBBase 
{
public:
	FlowDBBase(const std::string& host, const uint16_t port, const std::string& username, const std::string& password);

	virtual Flow* getNextFlow() = 0;
	virtual void connect(const std::string& database_name) = 0;
	virtual void getTableNames() = 0;

	virtual void limitTableSpace(const std::vector<std::string>& tableNames);

protected:
	std::string host;
	uint16_t port;
	std::string username;
	std::string password;

	std::vector<std::string> tables;
	std::vector<std::string> columns;
	std::string columnNames;
	size_t currentTableIndex; 
};


FlowDBBase* createFlowDB(const std::string& type, const std::string& host, const uint16_t port, const std::string& username, const std::string& password);

#endif
