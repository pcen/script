#include "script.h"

#include <iostream>
#include <ctime>
#include <cstring>
#include <filesystem>
#include <unordered_map>

#include <unistd.h>
#include <limits.h>
#include <err.h>

#include "utils.h"
#include "closestream.h"
#include "debug.h"
#include "pty-session.h"

auto constexpr DEFAULT_TYPESCRIPT_FILENAME = "typescript";
auto constexpr FORMAT_TIMESTAMP_MAX = ((4*4+1)+11+9+4+1); // weekdays can be unicode

void usage(void) {
	FILE *out = stdout;
	fputs("\nUsage:\n", out);
	fprintf(out, " %s [options] [file]\n", program_invocation_short_name);

	fputs("\n", out);
	fputs("Make a typescript of a terminal session.\n", out);

	fputs("\nOptions:\n", out);
	fputs(" -I, --log-in <file>           log stdin to file\n", out);
	fputs(" -O, --log-out <file>          log stdout to file (default)\n", out);
	fputs(" -B, --log-io <file>           log stdin and stdout to file\n", out);
	fputs("\n", out);

	fputs(" -T, --log-timing <file>       log timing information to file\n", out);
	fputs(" -m, --logging-format <name>   force to 'classic' or 'advanced' format\n", out);
	fputs("\n", out);

	fputs(" -a, --append                  append to the log file\n", out);
	fputs(" -c, --command <command>       run command rather than interactive shell\n", out);
	fputs(" -e, --return                  return exit code of the child process\n", out);
	fputs(" -f, --flush                   run flush after each write\n", out);
	fputs("     --force                   use output file even when it is a link\n", out);
	fputs(" -E, --echo <when>             echo input in session (auto, always or never)\n", out);
	fputs(" -o, --output-limit <size>     terminate if output files exceed size\n", out);
	fputs(" -q, --quiet                   be quiet\n", out);
	fputs("\n", out);

	fputs(" -h, --help                    display this help\n", out);
	fputs(" -V, --version                 display version\n", out);

	exit(EXIT_SUCCESS);
}

void dieIfLink(const ScriptControl& ctl, const char *filename) {
	if (ctl.force) {
		return;
	}
	if (std::filesystem::is_symlink(std::filesystem::path(filename))) {
		std::cerr << "output file: \"" << filename << "\" is a link" << std::endl;
		std::cerr << "Use --force if you really want to use it." << std::endl;
		std::cerr << "Program not started." << std::endl;
		exit(EXIT_FAILURE);
	}
}

const std::unordered_map<std::string, char> optNames = {
	{"--append", 'a'}, {"--command", 'c'}, {"--echo", 'E'}, {"--return", 'e'},
	{"--flush", 'f'}, {"--log-io", 'B'}, {"--log-in", 'I'}, {"--log-out", 'O'},
	{"--log-timing", 'T'}, {"--logging-format", 'm'}, {"--output-limit", 'o'},
	{"--quiet", 'q'}, {"--version", 'V'}, {"--help", 'h'},
};

std::unordered_map<char, std::string> parseArgs(ScriptControl& ctl, int& argCount, int argc, char *argv[]) {
	int i = 1;
	char c;
	std::unordered_map<char, std::string> valArgs;
	while (i < argc) {
		if (argv[i][0] == '-' && std::strlen(argv[i]) == 2) {
			c = argv[i][1];
		} else {
			auto it = optNames.find(argv[i]);
			if (it == optNames.end()) {
				std::cerr << "invalid option: " << argv[i] << std::endl;
				i++;
				continue;
			}
			c = it->second;
		}
		switch (c) {
			case 'a': // append to log
				ctl.append = true;
				break;
			case 'e': // return exit code
				ctl.rc_wanted = true;
				break;
			case 'f': // flush logs
				ctl.flush = true;
				break;
			case 'o': // max output size
				ctl.maxsz = std::stoul(std::string(argv[++i]));
				break;
			case 'q': // quiet mode
				ctl.quiet = true;
				break;

			case 'V': // version
				std::cout << "version 0.0.0" << std::endl;
				exit(EXIT_SUCCESS);
			case 'h': // usage
				usage();
				break;
			case 'c': // command
				std::cerr << "command mode not supported" << std::endl;
				exit(EXIT_FAILURE);
				break;

			case 'E': // echo
			case 'B': // both input and output
			case 'I': // input
			case 'O': // output
			case 'm': // log format
			case 'T': // timing file
				if (i < argc - 1) {
					valArgs[c] = std::string(argv[++i]);
					argCount++;
				} else {
					std::cerr << "missing value for option \"" << argv[i] << "\"" << std::endl;
					exit(EXIT_FAILURE);
				}
				break;
			default:
				std::cerr << "Try '" << program_invocation_name << "--help' for more information." << std::endl;
				exit(EXIT_FAILURE);
		}
		argCount++;
		i++;
	}
	return valArgs;
}

int main(int argc, char* argv[]) {
	ScriptControl ctl;
	ctl.out = ScriptStream('O');
	ctl.in = ScriptStream('I');

	ScriptFormat format = ScriptFormat::Invalid;
	int ch, caught_signal = 0, rc = 0, echo = 1;
	std::string outfile, infile, errfile, timingfile;
	const char *shell = nullptr, *command = nullptr;

	setlocale(LC_ALL, "");
	/*
	 * script -t prints time delays as floating point numbers.  The example
	 * program (scriptreplay) that we provide to handle this timing output
	 * is a perl script, and does not handle numbers in locale format (not
	 * even when "use locale;" is added).  So, since these numbers are not
	 * for human consumption, it seems easiest to set LC_NUMERIC here.
	 */
	setlocale(LC_NUMERIC, "C");
	close_stdout_atexit();

	ctl.isterm = isatty(STDIN_FILENO) == 1;

	int argCount = 1;
	std::unordered_map<char, std::string> argVals = parseArgs(ctl, argCount, argc, argv);
	for (auto [k, v] : argVals) {
		switch (k) {
			case 'E': // echo
				if (v == "auto") {
					;
				} else if (v == "never") {
					echo = 0;
				} else if (v == "always") {
					echo = 1;
				} else {
					std::cerr << "unsupported echo mode: " << v << std::endl;
				}
				break;
			case 'B': // both input and output
				ctl.associate(ctl.in, v, ScriptFormat::Raw);
				ctl.associate(ctl.out, v, ScriptFormat::Raw);
				infile = outfile = v;
				break;
			case 'I': // input
				ctl.associate(ctl.in, v, ScriptFormat::Raw);
				infile = v;
				break;
			case 'O': // output
				ctl.associate(ctl.out, v, ScriptFormat::Raw);
				outfile = v;
				break;
			case 'm': // log format
				if (v == "classic") {
					format = ScriptFormat::TimingSimple;
				} else if (v == "advanced") {
					format = ScriptFormat::TimingMulti;
				} else {
					std::cerr << "unsupported logging format: \"" << v << "\"" << std::endl;
					exit(EXIT_FAILURE);
				}
				break;
			case 'T': // timing file
				timingfile = v;
				break;
		}
	}
	argc -= argCount;
	argv += argCount;

	// default if no --log-* specified
	if (outfile.empty() && infile.empty()) {
		if (argc > 0) {
			outfile = argv[0];
		} else {
			dieIfLink(ctl, DEFAULT_TYPESCRIPT_FILENAME);
			outfile = DEFAULT_TYPESCRIPT_FILENAME;
		}

		// associate stdout with typescript file
		ctl.associate(ctl.out, outfile, ScriptFormat::Raw);
	}

	if (!timingfile.empty()) {
		/* the old SCRIPT_FMT_TIMING_SIMPLE should be used when
		 * recoding output only (just for backward compatibility),
		 * otherwise switch to new format. */
		if (format == ScriptFormat::Invalid) {
			format = !infile.empty() || (!outfile.empty() && !infile.empty()) ?
			         ScriptFormat::TimingMulti :
			         ScriptFormat::TimingSimple;
		} else if (format == ScriptFormat::TimingSimple && !outfile.empty() && !infile.empty()) {
			errx(EXIT_FAILURE, "log multiple streams is mutually exclusive with 'classic' format");
		}
		if (!outfile.empty()) {
			ctl.associate(ctl.out, timingfile, format);
		}
		if (!infile.empty()) {
			ctl.associate(ctl.in, timingfile, format);
		}
	}

	shell = getenv("SHELL");
	if (!shell) {
		std::cerr << "SHELL is not set" << std::endl;
		exit(EXIT_FAILURE);
	}

	ctl.pty = new Pty(ctl.isterm, ctl);
	if (!ctl.pty)
		err(EXIT_FAILURE, "failed to allocate PTY handler");

	ul_pty_slave_echo(ctl.pty, echo);

	if (!ctl.quiet) {
		std::cout << "Script started";
		if (!outfile.empty())
			std::cout << ", output log file is '" << outfile << "'";
		if (!infile.empty())
			std::cout << ", input log file is '" << infile << "'";
		if (!timingfile.empty())
			std::cout << ", timing file is '" << timingfile << "'";
		std::cout << std::endl;
	}

	if (ul_pty_setup(ctl.pty))
		err(EXIT_FAILURE, "failed to create pseudo-terminal");

	fflush(stdout);

	// we have terminal, do not use err() from now, use "goto done"
	switch ((int) (ctl.child = fork())) {
	case -1: // error
		warn("cannot create child process");
		rc = -errno;
		goto done;

	case 0: // child
	{
		const char *shname;

		ul_pty_init_slave(ctl.pty);

		signal(SIGTERM, SIG_DFL); // because /etc/csh.login

		shname = strrchr(shell, '/');
		shname = shname ? shname + 1 : shell;

		if (access(shell, X_OK) == 0) {
			if (command)
				execl(shell, shname, "-c", command, (char *)NULL);
			else
				execl(shell, shname, "-i", (char *)NULL);
		} else {
			if (command)
				execlp(shname, "-c", command, (char *)NULL);
			else
				execlp(shname, "-i", (char *)NULL);
		}

		err(EXIT_FAILURE, "failed to execute %s", shell);
		break;
	}
	default:
		break;
	}

	// parent
	ul_pty_set_child(ctl.pty, ctl.child);

	rc = ctl.loggingStart();
	if (rc)
		goto done;

	// add extra info to advanced timing file
	if (!timingfile.empty() && format == ScriptFormat::TimingMulti) {
		char buf[FORMAT_TIMESTAMP_MAX];
		time_t tvec = std::time(nullptr);
		std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&tvec));

		ctl.logInfo("START_TIME", std::string(buf));

		if (ctl.isterm) {
			ctl.initTerminalInfo();
			ctl.logInfo("TERM", std::string(ctl.ttytype));
			ctl.logInfo("TTY", std::string(ctl.ttyname));
			ctl.logInfo("COLUMNS", std::to_string(ctl.ttycols));
			ctl.logInfo("LINES", std::to_string(ctl.ttylines));
		}
		ctl.logInfo("SHELL", std::string(shell));
		if (command) {
			ctl.logInfo("COMMAND", std::string(command));
		}
		ctl.logInfo("TIMING_LOG", timingfile);
		if (!outfile.empty()) {
			ctl.logInfo("OUTPUT_LOG", outfile);
		}
		if (!infile.empty()) {
			ctl.logInfo("INPUT_LOG", infile);
		}
	}

	// this is the main loop
	rc = ul_pty_proxy_master(ctl.pty);

	// all done; cleanup and kill
	caught_signal = ul_pty_get_delivered_signal(ctl.pty);

	if (!caught_signal && ctl.child != (pid_t)-1)
		ul_pty_wait_for_child(ctl.pty); // final wait

	if (caught_signal && ctl.child != (pid_t)-1) {
		std::cerr << "\nSession terminated, killing shell...";
		kill(ctl.child, SIGTERM);
		sleep(2);
		kill(ctl.child, SIGKILL);
		std::cerr << " ...killed.\n";
	}

done:
	ul_pty_cleanup(ctl.pty);
	ctl.loggingDone(nullptr);

	if (!ctl.quiet)
		std::cout << "Script done." << std::endl;

	delete ctl.pty;

	/* default exit code */
	rc = rc ? EXIT_FAILURE : EXIT_SUCCESS;

	/* exit code based on child status */
	if (ctl.rc_wanted && rc == EXIT_SUCCESS) {
		if (WIFSIGNALED(ctl.childstatus))
			rc = WTERMSIG(ctl.childstatus) + 0x80;
		else
			rc = WEXITSTATUS(ctl.childstatus);
	}

	DBG("done [rc="<< rc << "]");
	return rc;
}
