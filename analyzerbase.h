#ifndef _FLOWGREPPER_ANALYZER_BASE_H_
#define _FLOWGREPPER_ANALYZER_BASE_H_

class Flow;
class ReporterBase;

class AnalyzerBase
{
public:
	AnalyzerBase(ReporterBase* reporter);
	
	virtual void analyzeFlow(const Flow* flow) = 0;
	virtual	void passResults() = 0;
protected:
	ReporterBase* reporter;
};

#endif
