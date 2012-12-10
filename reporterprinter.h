#ifndef _FLOWGREPPER_REPORTER_PRINTER_H_
#define _FLOWGREPPER_REPORTER_PRINTER_H_

#include "reporterbase.h"

class ReporterPrinter : public ReporterBase
{
public:
	ReporterPrinter();
	virtual void addLogString(const std::string& logMessage);

};

#endif 
