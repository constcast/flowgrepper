#ifdef ORACLE_SUPPORT

#include "oracleflowdb.h"


#include <stdexcept>
#include <iostream>
#include <sstream>

#include "flow.h"

OracleFlowDB::OracleFlowDB(const std::string& host, const uint16_t port, const std::string& username, const std::string& password)
	: FlowDBBase(host, port, username, password), conn(NULL), env(NULL), statement(NULL), resultSet(NULL), firstOfTable(false)
{

}

void OracleFlowDB::connect(const std::string& databaseName)
{
        /** get the mysl init handle*/
	if (conn) {
		env->terminateConnection(conn);
	}

	try {
		env = oracle::occi::Environment::createEnvironment(oracle::occi::Environment::DEFAULT);
	} catch (oracle::occi::SQLException& ex) {
		throw std::runtime_error("ERROR connecting to Oracle DB while creating statement: " + ex.getMessage());
	}
	
	try {
		std::stringstream stream;
		stream << host << ":" << port << "/" << databaseName;
		conn = env->createConnection(username.c_str(), password.c_str(), stream.str().c_str());
	} catch (oracle::occi::SQLException& ex) {
		throw std::runtime_error("ERROR connecting to Oracle DB while creating connection: " + ex.getMessage());
	}
}

void OracleFlowDB::getTableNames()
{
	// get tables in database
        const char* wild = "'F!_\%' ESCAPE '!'";
	std::ostringstream sql;
	oracle::occi::Statement* stmt = NULL;
	oracle::occi::ResultSet* tableRS = NULL;
	
	sql << "SELECT table_name from user_tables WHERE table_name LIKE " << wild << " ORDER BY table_name ASC";
	std::cout << sql.str() << std::endl;;
	try {
		stmt = conn->createStatement(sql.str());
	} catch (oracle::occi::SQLException& ex) {
		throw std::runtime_error("ERROR getting tables from Oracle DB while creating statement: " + ex.getMessage());
	}

	try {
		stmt->setPrefetchRowCount(1);
		tableRS = stmt->executeQuery();
	} catch (oracle::occi::SQLException& ex) {
		conn->terminateStatement(stmt);
		throw std::runtime_error("ERROR getting tables from Oracle DB while executing statement: " + ex.getMessage());
	}

	if (!tableRS) {
		throw std::runtime_error("Error: no tables in oracle DB ");
	}

	try {
		while (tableRS->next()) {
			tables.push_back(tableRS->getString(1));
		}
		stmt->closeResultSet(tableRS);
		conn->terminateStatement(stmt);	
	} catch(oracle::occi::SQLException& ex) {
		conn->terminateStatement(stmt);
		throw std::runtime_error("ERROR getting tables from  Oracle DB while getting results: " + ex.getMessage());
	}

	std::cout << "Found tables: " << std::endl;
	for (size_t i = 0; i != tables.size(); ++i) {
		std::cout << "\t" << tables[i] << std::endl;
	}

}

Flow* OracleFlowDB::createFlowFromRow()
{
	Flow* result = new Flow();

	// oracle starts counting at 1
	for (size_t i = 0; i != columns.size(); ++i) {
		//std::cout << "\t" <<  columns[i] << ": " << dbRow[i] << std::endl ;
		result->setValue(columns[i], resultSet->getString(i + 1).c_str());
	}
	//std::cout << std::endl << "-------" << std::endl;
	if (firstOfTable) {
		result->firstOfNewTable = true;
		firstOfTable = false;
	} else {
		result->firstOfNewTable = false;
	}


	return result;
	
}

void OracleFlowDB::fillColumns(const std::string& tableName)
{
	oracle::occi::Statement *stmt = NULL;
	oracle::occi::ResultSet* colRS = NULL;

	std::string query = "SELECT column_name FROM cols WHERE table_name = '" + tableName + "'";
	try {
		stmt = conn->createStatement(query);
	} catch (oracle::occi::SQLException& ex) {
		throw std::runtime_error("ERROR filling columnsOracle DB while creating statement: " + ex.getMessage());
	}

	try {
		stmt->setPrefetchRowCount(1);
		colRS = stmt->executeQuery();
	} catch (oracle::occi::SQLException& ex) {
		conn->terminateStatement(stmt);
		throw std::runtime_error("ERROR filling columns from Oracle DB executing statement: " + ex.getMessage());
	}

	if (!colRS) {
		throw std::runtime_error("Error: Oracle table " + tableName + " does not contain columns?!?");
	}

        columns.clear();
        columnNames = "";
	bool first = true;
	try {
	        while(colRS->next()) {
			columns.push_back(colRS->getString(1));
			if (!first)
				columnNames += ",";
			columnNames += std::string(colRS->getString(1));
			first = false;
		}
		stmt->closeResultSet(colRS);
		conn->terminateStatement(stmt);
	} catch (oracle::occi::SQLException& ex) {
		stmt->closeResultSet(colRS);
		conn->terminateStatement(stmt);
		throw std::runtime_error("ERROR filling columns from  Oracle DB while fetching results: " + ex.getMessage());
	}
	
}

Flow* OracleFlowDB::getNextFlow() 
{
	// check if we have flows from the last db fetch
	if (resultSet) {
		if (!resultSet->next()) {
			statement->closeResultSet(resultSet);
			conn->terminateStatement(statement);
			statement = NULL;
			resultSet = NULL;
			return getNextFlow();
		} else {
			return createFlowFromRow();
		}
	}

	// out of flows -> fetch next table!
	if (currentTableIndex >= tables.size()) {
		// no more tables. Return NULL to indicate we are finished
		return NULL;	
	}

	fillColumns(tables[currentTableIndex]);

	firstOfTable = true;

	std::cout << currentTableIndex << " " << tables.size() << std::endl;
	std::cout << tables[currentTableIndex] << std::endl;
        std::string query = "SELECT " + columnNames + " FROM " + tables[currentTableIndex] + " ";
	std::cout << "fetching flows with: " << query << std::endl;

	try {
		statement = conn->createStatement(query);
	} catch (oracle::occi::SQLException& ex) {
		throw std::runtime_error("ERROR fetching flows from Oracle DB while creating statement: " + ex.getMessage());
	}

	try {
		statement->setPrefetchRowCount(1000000);
		resultSet = statement->executeQuery();
	} catch (oracle::occi::SQLException& ex) {
		conn->terminateStatement(statement);
		throw std::runtime_error("ERROR fetching flows from Oracle DB while executing statement: " + ex.getMessage());
	}

	if (!resultSet) {
		throw std::runtime_error("Error: Oracle table " + tables[currentTableIndex] + " does not contain any flows?!?");
	}

	++currentTableIndex;
	return getNextFlow();
}

#endif
