#include "configobject.h"

#include <algorithm>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <iostream>

ConfigObject::ConfigObject(const std::string& filename)
{
	d = iniparser_new(filename.c_str());
	if (!d) {
		throw std::runtime_error("ConfigObject: Could not parse config file " + filename + "!");
	}
}

ConfigObject::~ConfigObject()
{
	iniparser_free(d);
}

std::string ConfigObject::getConfString(const std::string& section, const std::string& key) const
{
	return iniparser_getvalue(d, section.c_str(), key.c_str());
}

