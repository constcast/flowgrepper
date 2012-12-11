#include "configobject.h"

#include <algorithm>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <iostream>

ConfigObject::ConfigObject(const std::string& filename)
{
	// parse config
	std::ifstream configStream;
	configStream.open(filename.c_str());
	std::string  line;

	while (std::getline(configStream, line)) {
		size_t found = line.find("=");
		if (found == std::string::npos) {
			// no = in stringk
			throw std::runtime_error("Config Error: Could not find = in config string \"" + line + "\"");
		}
		std::string key = line.substr(0, found);
		std::string value = line.substr(found + 1, line.size());
		std::cout << key << " " << value << std::endl;
		confStrings[key] = value;
	}
}

std::string ConfigObject::getConfString(const std::string& section, const std::string& key) const
{
	if (confStrings.find(key) == confStrings.end()) {
		throw std::runtime_error("Config Error: Could not find \"" + key + "\" in config file");
	}
	return confStrings.find(key)->second;
}

