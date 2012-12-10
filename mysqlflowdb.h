#ifndef _FLOWGREPPER_MYSQL_FLOW_DB_H_
#define _FLOWGREPPER_MYSQL_FLOW_DB_H_

#include "flowdb.h"

#include <string>
#include <vector>

#include <mysql.h>


class MySQLFlowDB : public FlowDBBase
{
public:
	MySQLFlowDB(const std::string& host, const uint16_t port, const std::string& username, const std::string& password);

	virtual Flow* getNextFlow();
	virtual void connect(const std::string& databaseName);
	virtual Flow* createFlowFromRow(char** dbRow);

private: 
	void fillColumns(const std::string& tableName);

	MYSQL* conn;
	MYSQL_RES* dbResult;
	std::vector<std::string> tables;
	std::vector<std::string> columns;
	std::string columnNames;
	size_t currentTableIndex; 
};

#endif
