#ifndef _FLOWGREPPER_MYSQL_FLOW_DB_H_
#define _FLOWGREPPER_MYSQL_FLOW_DB_H_

#ifdef MYSQL_SUPPORT

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
	virtual void getTableNames();

private: 
	void fillColumns(const std::string& tableName);
	Flow* createFlowFromRow(char** dbRow);

	MYSQL* conn;
	MYSQL_RES* dbResult;
	bool firstOfTable;
};

#endif

#endif
