#ifndef SCRIPT_H
#define SCRIPT_H

#include <vector>
#include <string>

#include "pty-session.h"

enum class ScriptFormat {
	Invalid = 0,
	Raw, // raw slave/master data
	TimingSimple, // (classic) in format "<delta> <offset>"
	TimingMulti, // (advanced) multiple streams in format "<type> <delta> <offset|etc>
};

class ScriptLog {
public:
	FILE *fp; // file pointer
	ScriptFormat format;
	std::string filename; // on command line specified name
	struct timeval oldtime; // previous entry log time (timing script only)
	struct timeval starttime;
	bool initialized;

	ScriptLog();
	int flush();
	int write(const char* fmt, ...);
};

class ScriptStream {
public:
	std::vector<ScriptLog*> logs; // logs where to write data from stream
	char ident; // stream identifier
	ScriptStream(char ident = '\0');
	ScriptLog* getLogByName(const std::string& name);
	bool operator==(const ScriptStream& rhs) const;
};

class ScriptControl : public PtyCallback {
public:
	uint64_t outsz; // current output files size
	uint64_t maxsz; // maximum output files size

	ScriptStream out; // output
	ScriptStream in; // input
	ScriptStream err; // error

	ScriptLog *siglog; // log for signal entries
	ScriptLog *infolog; // log for info entries

	const char *ttyname;
	const char *ttytype;
	int ttycols;
	int ttylines;

	struct Pty *pty; // pseudo-terminal
	pid_t child; // child pid
	int childstatus; // child process exit value

	bool append; // append output
	bool rc_wanted; // return child exit value
	bool flush; // flush after each write
	bool quiet; // suppress most output
	bool force; // write output to links
	bool isterm; // is child process running as terminal

	ScriptControl();
	void initTerminalInfo();
	ScriptLog* associate(ScriptStream& stream, const std::string& filename, ScriptFormat format);
	int loggingStart();

	ssize_t logWrite(ScriptStream& stream, ScriptLog* log, char* obuf, size_t bytes);
	ssize_t logStreamActivity(ScriptStream& stream, char* buf, size_t bytes);
	ssize_t logSignal(int signum, const char *msgfmt, ...);
	ssize_t logInfo(const char* name, const char* msgfmt, ...);

	void loggingDone(const char* msg);
	int closeLog(ScriptLog* log, const char* msg, int status);

	void deleteLog(ScriptLog* log);
	int startLog(ScriptLog* log);

	// pty callback methods
	void ptyChildDie(pid_t, int) override;
	void ptyChildSigstop(pid_t) override;
	int ptyLogStreamActivity(int, char*, size_t) override;
	int ptyLogSignal(struct signalfd_siginfo*, void*) override;
	int ptyFlushLogs() override;
};

#endif // SCRIPT_H
