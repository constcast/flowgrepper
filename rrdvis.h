#ifndef _FLOWGREPPER_RRD_VIS_H_
#define _FLOWGREPPER_RRD_VIS_H_

#include "analyzerbase.h"

#include <map>
#include <stdint.h>
#include <string>
extern "C" {
#include "longest-prefix/tree.h"
}


class RRDVisAnalyzer : public AnalyzerBase
{
public:
	RRDVisAnalyzer(const ConfigObject& configObject, ReporterBase& reporter);
	~RRDVisAnalyzer();
	
	virtual void analyzeFlow(const Flow* flow);
	virtual	void passResults();
	virtual void nextTable();

	struct SubnetStats {

	};

private:
	std::string configFile;
	std::string rrdPath;
	std::string rrdDbPath;

	const std::string configSection;
	struct lpm_tree* tree;
};

#endif
