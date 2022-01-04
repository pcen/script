#ifndef SCRIPT_H
#define SCRIPT_H

#include <vector>
#include <string>

enum class ScriptFormat {
	Invalid = 0,
	Raw, // raw slave/master data
	TimingSimple, // (classic) in format "<delta> <offset>"
	TimingMulti, // (advanced) multiple streams in format "<type> <delta> <offset|etc>
};

class ScriptLog {
public:
	FILE *fp; // file pointer (handler)
	ScriptFormat format;
	std::string filename; // on command line specified name
	struct timeval oldtime; // previous entry log time (timing script only)
	struct timeval starttime;
	unsigned int initialized;

	ScriptLog() : fp{ nullptr }, initialized{ 0 } {}
};

class ScriptStream {
public:
	std::vector<ScriptLog*> logs; // logs where to write data from stream
	char ident; // stream identifier
	ScriptStream(char ident = '\0');
	ScriptLog* getLogByName(const std::string& name);
};

class ScriptControl {
public:
	uint64_t outsz; // current output files size
	uint64_t maxsz; // maximum output files size

	ScriptStream out; // output
	ScriptStream in; // input

	ScriptLog *siglog; // log for signal entries
	ScriptLog *infolog; // log for info entries

	const char *ttyname;
	const char *ttytype;
	int ttycols;
	int ttylines;

	struct ul_pty *pty; // pseudo-terminal
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
	ScriptLog* associate(ScriptStream* stream, const std::string& filename, ScriptFormat format);
};

void callback_child_die(void* data, pid_t child, int status);
void callback_child_sigstop(void* data, pid_t child);
int callback_log_stream_activity(void* data, int fd, char* buf, size_t bufsz);
int callback_log_signal(void* data, struct signalfd_siginfo* info, void* sigdata);
int callback_flush_logs(void* data);
int logging_start(ScriptControl *ctl);
ssize_t log_info(ScriptControl *ctl, const char *name, const char *msgfmt, ...);
void logging_done(ScriptControl *ctl, const char *msg);

#endif // SCRIPT_H
