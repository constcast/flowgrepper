PROJECT(flowgrepper)


CMAKE_MINIMUM_REQUIRED(VERSION 2.5)
SET(CMAKE_MODULE_PATH ${CMAKE_ROOT}/Modules ${CMAKE_SOURCE_DIR}/cmake/modules)

ADD_EXECUTABLE(flowgrepper
	flowgrepper.cpp
	mysqlflowdb.cpp
	flowdb.cpp
	flow.cpp

	analyzerbase.cpp
	onewayflowanalyzer.cpp

	reporterbase.cpp
	reporterprinter.cpp
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
        ADD_DEFINITIONS(-DDB_SUPPORT_ENABLED)
        INCLUDE_DIRECTORIES(${MYSQL_INCLUDE_DIR})
        TARGET_LINK_LIBRARIES(flowgrepper
                ${MYSQL_LIBRARIES}
        )
ELSE (MYSQL_FOUND AND SUPPORT_MYSQL)
        REMOVE_DEFINITIONS(-DDB_SUPPORT_ENABLED)
ENDIF (MYSQL_FOUND AND SUPPORT_MYSQL)
