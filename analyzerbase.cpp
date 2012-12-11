#include "analyzerbase.h"

AnalyzerBase::AnalyzerBase(const ConfigObject& confObject, ReporterBase& report)
	: configObject(confObject), reporter(report)
{

}
