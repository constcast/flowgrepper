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
	: host(host), port(port), username(username), password(password)
{

}

