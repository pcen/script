#ifndef MONITOR_H
#define MONITOR_H

#include <vector>
#include <deque>
#include <string>
#include <cstdint>

struct Line {
	int64_t timestamp;
	std::string text;
	Line(int64_t timestamp, const std::string& text);
};

class Monitor {
public:
	Monitor();
	~Monitor();
	void onOutput(char* buf, std::size_t bytes);

private:
	void parseCommand(const std::string& line);

	std::vector<char> cmd;
	std::deque<char> output;
	std::vector<Line> commands;
	std::vector<Line> lines;
};

#endif // MONITOR_H
