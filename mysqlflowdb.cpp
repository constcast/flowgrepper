#ifdef MYSQL_SUPPORT

#include "mysqlflowdb.h"


#include <stdexcept>
#include <iostream>

#include "flow.h"

MySQLFlowDB::MySQLFlowDB(const std::string& host, const uint16_t port, const std::string& username, const std::string& password)
	: FlowDBBase(host, port, username, password), conn(NULL), dbResult(NULL), firstOfTable(true)
{
	flow = new Flow();
}

MySQLFlowDB::~MySQLFlowDB()
{

}

void MySQLFlowDB::connect(const std::string& databaseName)
{
        /** get the mysl init handle*/
        conn = mysql_init(0);
        if(conn == 0) {
                throw std::runtime_error("Could not init mysql: " + std::string(mysql_error(conn)));
        } else {
		std::cout << "Initialized MySQL conn ..." << std::endl;
        }

        /**Connect to Database*/
        if (!mysql_real_connect(conn, host.c_str(), username.c_str(), password.c_str(), 0, port, 0, 0)) {
                throw std::runtime_error("Could not connect to mysql database: " + std::string(mysql_error(conn)));
        } else {
                std::cout << "Successfully connected to mysql db ..." << std::endl;
        }

        if(mysql_select_db(conn, databaseName.c_str()) !=0) {
		throw std::runtime_error("Could not select datatbase " + databaseName + mysql_error(conn));
        } else {
		std::cout << "Successfully selected database " << databaseName << std::endl;
        }
}


void MySQLFlowDB::getTableNames()
{
	// get tables in database
        const char* wild = "f\\_%";
	MYSQL_RES* dbTableResult = NULL;
	MYSQL_ROW dbRow = NULL;
	
	dbTableResult = mysql_list_tables(conn, wild);
	if(dbTableResult == 0) {
		throw std::runtime_error("Database does not contain any tables!");
	} else {
		while((dbRow = mysql_fetch_row(dbTableResult))) {
			tables.push_back(std::string(dbRow[0]));
			std::cout << "Found table: " << tables.back() << std::endl;
		}
	}

        mysql_free_result(dbTableResult);
}

Flow* MySQLFlowDB::createFlowFromRow(char** dbRow)
{
	for (size_t i = 0; i != columns.size(); ++i) {
		//std::cout << "\t" <<  columns[i] << ": " << dbRow[i] << std::endl ;
		flow->setValue(columns[i], dbRow[i]);
	}
	//std::cout << std::endl << "-------" << std::endl;
	if (firstOfTable) {
		flow->firstOfNewTable = true;
		firstOfTable = false;
	} else {
		flow->firstOfNewTable = false;
	}

	return flow;
	
}

void MySQLFlowDB::fillColumns(const std::string& tableName)
{
	MYSQL_RES* dbColumnResult = NULL;
	MYSQL_ROW dbRow = NULL;
	
	std::string query = "SHOW COLUMNS FROM " + tableName;
	if(mysql_query(conn, query.c_str()) != 0) {
		throw std::runtime_error("Error fetching columns from table " + tableName + ": " +  mysql_error(conn));
	}
	
	dbColumnResult = mysql_store_result(conn);
	
	if(dbColumnResult == 0) {
		throw std::runtime_error("Error: There are no columns in table " + tableName + "!");
        }

        columns.clear();
        columnNames = "";
	bool first = true;
        while((dbRow = mysql_fetch_row(dbColumnResult))) {
		columns.push_back(dbRow[0]);
		if (!first)
			columnNames += ",";
		columnNames += std::string(dbRow[0]);
		first = false;
	}
	mysql_free_result(dbColumnResult);
}

Flow* MySQLFlowDB::getNextFlow() 
{
	// check if we have flows from the last db fetch
	if (dbResult) {
		MYSQL_ROW dbRow = mysql_fetch_row(dbResult); 
		if (!dbRow) {
			mysql_free_result(dbResult);
			dbResult = NULL;
			return getNextFlow();
		}
		return createFlowFromRow(dbRow);
	}

	// out of flows -> fetch next table!
	if (currentTableIndex >= tables.size()) {
		// no more tables. Return NULL to indicate we are finished
		return NULL;	
	}

	fillColumns(tables[currentTableIndex]);

	std::cout << currentTableIndex << " " << tables.size() << std::endl;
	std::cout << tables[currentTableIndex] << std::endl;
	//std::string query = "SELECT " + columnNames + " FROM " + tables[currentTableIndex];
        std::string query = "SELECT " + columnNames + " FROM " + tables[currentTableIndex] + " ORDER BY flowStartMilliSeconds";
	std::cout << query << std::endl;

	firstOfTable = true;

        if(mysql_query(conn, query.c_str()) != 0) {
                throw std::runtime_error("Error running query on table " + tables[currentTableIndex] + ": " +  std::string(mysql_error(conn)));
        }

        //dbResult = mysql_store_result(conn);
        dbResult = mysql_store_result(conn);
	if (dbResult == 0) {
		// some kind of error? 
		throw std::runtime_error("Error storing query result for table " + tables[currentTableIndex] + ": " + std::string(mysql_error(conn)));
	}

	++currentTableIndex;
	return getNextFlow();
}

#endif
