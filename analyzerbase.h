#ifndef _FLOWGREPPER_ANALYZER_BASE_H_
#define _FLOWGREPPER_ANALYZER_BASE_H_

#include "configobject.h"

class Flow;
class ReporterBase;

class AnalyzerBase
{
public:
	AnalyzerBase(const ConfigObject& configObject, ReporterBase& reporter);
	
	virtual void analyzeFlow(const Flow* flow) = 0;
	virtual void nextTable() {};
	virtual	void passResults() = 0;
protected:
	const ConfigObject& configObject;
	ReporterBase& reporter;
};

#endif
