#ifndef _FLOWGREPPER_CONFIG_OBJECT_H_
#define _FLOWGREPPER_CONFIG_OBJECT_H_

#include <string>
#include <map>

#include "iniparser.h"

class ConfigObject
{
public:
	ConfigObject(const std::string& file);
	~ConfigObject();
	virtual std::string getConfString(const std::string& section, const std::string& key) const;
private:
	dictionary* d;
};

#endif
