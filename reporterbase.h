#ifndef _FLOWGREPPER_REPORTER_H_
#define _FLOWGREPPER_REPORTER_H_

#include <string>

class ReporterBase
{
public:
	ReporterBase() {};
	virtual void addLogString(const std::string& logMessage) = 0;
};

#endif 
