#include "flowdb.h"

#include "mysqlflowdb.h"
#include "oracleflowdb.h"

#include <stdexcept>

static FlowDBBase* flowdb;

FlowDBBase* createFlowDB(const std::string& type, const std::string& host, const uint16_t port, const std::string& username, const std::string& password)
{
	if (type == "mysql") {
#ifdef MYSQL_SUPPORT
		flowdb = new MySQLFlowDB(host, port, username, password);
#else
		throw std::runtime_error("MYSQL support has been turned off at compile time!");
#endif
	} else if (type == "oracle") {
#ifdef ORACLE_SUPPORT
		flowdb = new OracleFlowDB(host, port, username, password);
#else
		throw std::runtime_error("Oracle support has been turned off at compile time!");
#endif
	} else {
		throw std::runtime_error("Not supported database backend " + type);
	}

	return flowdb;
}


//// class

FlowDBBase::FlowDBBase(const std::string& host, const uint16_t port, const std::string& username, const std::string& password)
	: host(host), port(port), username(username), password(password), currentTableIndex(0)
{

}

void FlowDBBase::limitTableSpace(const std::vector<std::string>& tableNames)
{
	std::vector<std::string> filteredTables;
	for (size_t i = 0; i != tables.size(); ++i) {
		bool keepTable = false;
		for (size_t j = 0; j != tableNames.size(); ++j) {
			if (tables[i] == tableNames[j]) {
				// table is allowed, do not remove it
				keepTable = true;
			}	
		}
		if (keepTable) {
			filteredTables.push_back(tables[i]);
		}
	}
	if (filteredTables.size() == 0 && tableNames.size() != 0){
		throw std::runtime_error("ERROR: FlowDBBase::limitTableSpace: No tables remaining after filtering ...");
	}
	tables = filteredTables;
}

