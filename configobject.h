#ifndef _FLOWGREPPER_CONFIG_OBJECT_H_
#define _FLOWGREPPER_CONFIG_OBJECT_H_

#include <string>
#include <map>

class ConfigObject
{
public:
	ConfigObject(const std::string& file);
	virtual std::string getConfString(const std::string& section, const std::string& key) const;
protected:
	std::map<std::string, std::string> confStrings;	
};

#endif
