#ifndef _FLOWGREPPER_ORACLE_FLOW_DB_H_
#define _FLOWGREPPER_ORACLE_FLOW_DB_H_

#ifdef ORACLE_SUPPORT

#include "flowdb.h"

#include <string>
#include <vector>

#include <occi.h>


class OracleFlowDB : public FlowDBBase
{
public:
	OracleFlowDB(const std::string& host, const uint16_t port, const std::string& username, const std::string& password);

	virtual Flow* getNextFlow();
	virtual void connect(const std::string& databaseName);
	virtual void getTableNames();

private: 
	void fillColumns(const std::string& tableName);
	Flow* createFlowFromRow();

	bool dbError;
	oracle::occi::Connection *conn;
	oracle::occi::Environment *env;
	oracle::occi::Statement *statement;
	oracle::occi::ResultSet *resultSet;
	
	bool firstOfTable;
};

#endif

#endif
