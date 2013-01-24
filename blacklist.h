#ifndef _FLOWGREPPER_BLACKLIST_H_
#define _FLOWGREPPER_BLACKLIST_H_

#include <string>
#include <map>
#include <stdint.h>

extern "C" {
#include "longest-prefix/tree.h"
}

enum Type {IP, NET, ONLINE, LIST};

class Blacklist
{
public:
	Blacklist(const std::string, unsigned int, Type);
	std::string GetName();
	int GetLength();
	unsigned char* GetIPs();
	void PrintIP(unsigned char*);
	void PrintNet(unsigned char*);
	int IsIn(uint32_t, char**);

private:
	std::string listname;
	int index;	
	Type type;
	int elements;
	unsigned char* ips;
	
	struct lpm_tree* tree;
};

#endif
