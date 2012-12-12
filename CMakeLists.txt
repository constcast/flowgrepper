PROJECT(flowgrepper)


CMAKE_MINIMUM_REQUIRED(VERSION 2.5)
SET(CMAKE_MODULE_PATH ${CMAKE_ROOT}/Modules ${CMAKE_SOURCE_DIR}/cmake/modules)

ADD_EXECUTABLE(flowgrepper
	flowgrepper.cpp
	configobject.cpp
	flow.cpp
	iniparser.c
	

	flowdb.cpp
	oracleflowdb.cpp
	mysqlflowdb.cpp

	analyzerbase.cpp
	onewayflowanalyzer.cpp
	rrdvis.cpp

	reporterbase.cpp
	reporterprinter.cpp
	longest-prefix/tree.c
)

ADD_DEFINITIONS(-O0 -g -pg -Wall -DDEBUG)
SET_TARGET_PROPERTIES(flowgrepper PROPERTIES LINK_FLAGS "-g -pg")

OPTION(SUPPORT_MYSQL "Enable MYSQL support" ON)
IF (SUPPORT_MYSQL)
        FIND_PACKAGE(MySQL REQUIRED)
        MARK_AS_ADVANCED(
                MYSQL_ADD_INCLUDE_DIR
                MYSQL_ADD_LIBRARY
                MYSQL_CONFIG
                MYSQL_CONFIG_PREFER_PATH
        )
        IF (NOT MYSQL_FOUND)
                MESSAGE(FATAL_ERROR "Could not find MySQL libraries.")
        ENDIF (NOT MYSQL_FOUND)
ENDIF (SUPPORT_MYSQL)
IF (MYSQL_FOUND AND SUPPORT_MYSQL)
        MESSAGE(STATUS "Found MySQL libraries")
        ADD_DEFINITIONS(-DMYSQL_SUPPORT)
        INCLUDE_DIRECTORIES(${MYSQL_INCLUDE_DIR})
        TARGET_LINK_LIBRARIES(flowgrepper
                ${MYSQL_LIBRARIES}
        )
ELSE (MYSQL_FOUND AND SUPPORT_MYSQL)
        REMOVE_DEFINITIONS(-DMYSQL_SUPPORT)
ENDIF (MYSQL_FOUND AND SUPPORT_MYSQL)

### Oracle

OPTION(SUPPORT_ORACLE "Enable Oracle support" OFF)
IF (SUPPORT_ORACLE)
	FIND_PACKAGE(Oracle REQUIRED)
	IF (NOT ORACLE_FOUND)
		MESSAGE(FATAL_ERROR "Could not find Oracle libraries.")
	ENDIF (NOT ORACLE_FOUND)
ENDIF (SUPPORT_ORACLE)
IF (ORACLE_FOUND)
	MESSAGE(STATUS "Found Oracle libraries")
	ADD_DEFINITIONS(-DORACLE_SUPPORT)
	INCLUDE_DIRECTORIES(${ORACLE_INCLUDE_DIR})
	TARGET_LINK_LIBRARIES(flowgrepper
		${ORACLE_CONNECTION_LIBRARIES}
	)
	TARGET_LINK_LIBRARIES(flowgrepper
		${ORACLE_CLIENT_LIBRARIES}
	)	
ELSE (ORACLE_FOUND)
	REMOVE_DEFINITIONS(-DORACLE_SUPPORT)
ENDIF (ORACLE_FOUND)


