FIND_PATH(RRD_INCLUDE_DIR rrd.h PATHS
	/usr/include
	/usr/local/include
	/opt/data/software/include/	
)

IF (RRD_INCLUDE_DIR)
	SET(FOUND_RRD true)
ENDIF(RRD_INCLUDE_DIR)

IF(NOT RRD_HEADER)
	MESSAGE(FATAL_ERROR "includes for librrd not found.")
ENDIF(NOT RRD_HEADER)

FIND_LIBRARY(RRD_LIBRARIES rrd PATHS 
	/usr/lib/
	/usr/local/lib
	/opt/data/software/lib
)
IF(NOT RRD_LIBRARIES)
	message(FATAL_ERROR "librrd not found.")
ENDIF(NOT RRD_LIBRARIES)

