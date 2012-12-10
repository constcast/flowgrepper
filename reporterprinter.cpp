#include "reporterprinter.h"

#include <iostream>

ReporterPrinter::ReporterPrinter()
	: ReporterBase()
{

}

void ReporterPrinter::addLogString(const std::string& logMessage)
{
	std::cout << logMessage << std::endl;
}

