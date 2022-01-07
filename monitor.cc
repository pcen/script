#include "monitor.h"

#include <istream>
#include <streambuf>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <iostream>

#include <iostream>
#include <chrono>
#include <list>
#include <cctype>

int64_t unixTime() {
	auto s = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
	return s.time_since_epoch().count();
}

Line::Line(int64_t timestamp, const std::string& text) : timestamp{ timestamp }, text{ text } {}

Monitor::Monitor() {

}

Monitor::~Monitor() {
	for (int i = 0; i < lines.size(); i++) {
		std::cerr << "line " << i << ": " << lines.at(i).text << std::endl;
	}
	for (int i = 0; i < commands.size(); i++) {
		std::cerr << "command " << i << ": " << commands.at(i).text << std::endl;
	}
}

void Monitor::parseCommand(const std::string& line) {
	int i = 0;
	while (i < line.size() && line[i] != '$') {
		i++;
	}
	if (line[++i] == ' ') {
		commands.push_back(Line(unixTime(), line.substr(++i)));
	}
}

void Monitor::onOutput(char* buf, std::size_t bytes) {
	output.insert(output.end(), buf, buf + bytes);

getLineFromBuffer:
	int s = output.size();
	for (int i = 0; i < s - 1; i++) {
		if (output.at(i) == '\r' && output.at(i + 1) == '\n') {
			std::string line = std::string(output.begin(), output.begin() + i); // exclude \r\n
			parseCommand(line);

			lines.push_back(Line(unixTime(), line));
			output.erase(output.begin(), output.begin() + i + 2); // remove up to and including i + 1 which is \n
			goto getLineFromBuffer;
		}
	}
}
