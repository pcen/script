#include "script.h"

#include <iostream>
#include <ctime>

#include <getopt.h>
#include <unistd.h>
#include <limits.h>
#include <err.h>

#include "utils.h"
#include "optutils.h"
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
	fputs(" -t[<file>], --timing[=<file>] deprecated alias to -T (default file is stderr)\n", out);
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

void die_if_link(const ScriptControl& ctl, const char *filename) {
	struct stat s;

	if (ctl.force)
		return;
	if (lstat(filename, &s) == 0 && (S_ISLNK(s.st_mode) || s.st_nlink > 1))
		errx(EXIT_FAILURE,
		       "output file `%s' is a link\n"
		       "Use --force if you really want to use it.\n"
		       "Program not started.", filename);
}

int main(int argc, char **argv)
{
	ScriptControl ctl;
	ctl.out = ScriptStream('O');
	ctl.in = ScriptStream('I');

	struct ul_pty_callbacks *cb;
	ScriptFormat format = ScriptFormat::Invalid;
	int ch, caught_signal = 0, rc = 0, echo = 1;
	const char *outfile = NULL, *infile = NULL;
	const char *timingfile = NULL, *shell = NULL, *command = NULL;

	enum { FORCE_OPTION = CHAR_MAX + 1 };

	static const struct option longopts[] = {
		{"append", no_argument, NULL, 'a'},
		{"command", required_argument, NULL, 'c'},
		{"echo", required_argument, NULL, 'E'},
		{"return", no_argument, NULL, 'e'},
		{"flush", no_argument, NULL, 'f'},
		{"force", no_argument, NULL, FORCE_OPTION,},
		{"log-in", required_argument, NULL, 'I'},
		{"log-out", required_argument, NULL, 'O'},
		{"log-io", required_argument, NULL, 'B'},
		{"log-timing", required_argument, NULL, 'T'},
		{"logging-format", required_argument, NULL, 'm'},
		{"output-limit", required_argument, NULL, 'o'},
		{"quiet", no_argument, NULL, 'q'},
		{"timing", optional_argument, NULL, 't'},
		{"version", no_argument, NULL, 'V'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	static const ul_excl_t excl[] = {       /* rows and cols in ASCII order */
		{ 'T', 't' },
		{ 0 }
	};
	int excl_st[ARRAY_SIZE(excl)] = UL_EXCL_STATUS_INIT;
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

	while ((ch = getopt_long(argc, argv, "aB:c:eE:fI:O:o:qm:T:t::Vh", longopts, NULL)) != -1) {

		err_exclusive_options(ch, longopts, excl, excl_st);

		switch (ch) {
		case 'a':
			ctl.append = true;
			break;
		case 'c':
			command = optarg;
			break;
		case 'E':
			if (strcmp(optarg, "auto") == 0)
				; // keep default
			else if (strcmp(optarg, "never") == 0)
				echo = 0;
			else if (strcmp(optarg, "always") == 0)
				echo = 1;
			else
				errx(EXIT_FAILURE, "unssuported echo mode: '%s'", optarg);
			break;
		case 'e':
			ctl.rc_wanted = true;
			break;
		case 'f':
			ctl.flush = true;
			break;
		case FORCE_OPTION:
			ctl.force = true;
			break;
		case 'B':
			log_associate(&ctl, &ctl.in, optarg, ScriptFormat::Raw);
			log_associate(&ctl, &ctl.out, optarg, ScriptFormat::Raw);
			infile = outfile = optarg;
			break;
		case 'I':
			log_associate(&ctl, &ctl.in, optarg, ScriptFormat::Raw);
			infile = optarg;
			break;
		case 'O':
			log_associate(&ctl, &ctl.out, optarg, ScriptFormat::Raw);
			outfile = optarg;
			break;
		case 'o':
			ctl.maxsz = std::stoul(optarg);
			break;
		case 'q':
			ctl.quiet = true;
			break;
		case 'm':
			if (strcasecmp(optarg, "classic") == 0)
				format = ScriptFormat::TimingSimple;
			else if (strcasecmp(optarg, "advanced") == 0)
				format = ScriptFormat::TimingMulti;
			else
				errx(EXIT_FAILURE, "unsupported logging format: '%s'", optarg);
			break;
		case 't':
			if (optarg && *optarg == '=')
				optarg++;
			timingfile = optarg ? optarg : "/dev/stderr";
			break;
		case 'T' :
			timingfile = optarg;
			break;
		case 'V':
			printf("version 0.0.0\n");
			exit(EXIT_SUCCESS);
		case 'h':
			usage();
		default:
			fprintf(stderr, "Try '%s --help' for more information.\n", program_invocation_short_name);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	// default if no --log-* specified
	if (!outfile && !infile) {
		if (argc > 0) {
			outfile = argv[0];
		}
		else {
			die_if_link(ctl, DEFAULT_TYPESCRIPT_FILENAME);
			outfile = DEFAULT_TYPESCRIPT_FILENAME;
		}

		// associate stdout with typescript file
		log_associate(&ctl, &ctl.out, outfile, ScriptFormat::Raw);
	}

	if (timingfile) {
		/* the old SCRIPT_FMT_TIMING_SIMPLE should be used when
		 * recoding output only (just for backward compatibility),
		 * otherwise switch to new format. */
		if (format == ScriptFormat::Invalid) {
			format = infile || (outfile && infile) ?
			         ScriptFormat::TimingMulti :
			         ScriptFormat::TimingSimple;
		} else if (format == ScriptFormat::TimingSimple && outfile && infile) {
			errx(EXIT_FAILURE, "log multiple streams is mutually exclusive with 'classic' format");
		}
		if (outfile) {
			log_associate(&ctl, &ctl.out, timingfile, format);
		}
		if (infile) {
			log_associate(&ctl, &ctl.in, timingfile, format);
		}
	}

	shell = getenv("SHELL");
	if (!shell) {
		std::cerr << "SHELL is not set" << std::endl;
		exit(EXIT_FAILURE);
	}

	ctl.pty = ul_new_pty(ctl.isterm);
	if (!ctl.pty)
		err(EXIT_FAILURE, "failed to allocate PTY handler");

	ul_pty_slave_echo(ctl.pty, echo);

	ul_pty_set_callback_data(ctl.pty, (void *) &ctl);
	cb = ul_pty_get_callbacks(ctl.pty);
	cb->child_die = callback_child_die;
	cb->child_sigstop = callback_child_sigstop;
	cb->log_stream_activity = callback_log_stream_activity;
	cb->log_signal = callback_log_signal;
	cb->flush_logs = callback_flush_logs;

	if (!ctl.quiet) {
		printf("Script started");
		if (outfile)
			printf(", output log file is '%s'", outfile);
		if (infile)
			printf(", input log file is '%s'", infile);
		if (timingfile)
			printf(", timing file is '%s'", timingfile);
		printf(".\n");
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

	rc = logging_start(&ctl);
	if (rc)
		goto done;

	// add extra info to advanced timing file
	if (timingfile && format == ScriptFormat::TimingMulti) {
		char buf[FORMAT_TIMESTAMP_MAX];
		time_t tvec = std::time(nullptr);
		std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&tvec));

		log_info(&ctl, "START_TIME", "%s", buf);

		if (ctl.isterm) {
			init_terminal_info(&ctl);
			log_info(&ctl, "TERM", "%s", ctl.ttytype);
			log_info(&ctl, "TTY", "%s", ctl.ttyname);
			log_info(&ctl, "COLUMNS", "%d", ctl.ttycols);
			log_info(&ctl, "LINES", "%d", ctl.ttylines);
		}
		log_info(&ctl, "SHELL", "%s", shell);
		if (command)
			log_info(&ctl, "COMMAND", "%s", command);
		log_info(&ctl, "TIMING_LOG", "%s", timingfile);
		if (outfile)
			log_info(&ctl, "OUTPUT_LOG", "%s", outfile);
		if (infile)
			log_info(&ctl, "INPUT_LOG", "%s", infile);
	}

	// this is the main loop
	rc = ul_pty_proxy_master(ctl.pty);

	// all done; cleanup and kill
	caught_signal = ul_pty_get_delivered_signal(ctl.pty);

	if (!caught_signal && ctl.child != (pid_t)-1)
		ul_pty_wait_for_child(ctl.pty); // final wait

	if (caught_signal && ctl.child != (pid_t)-1) {
		fprintf(stderr, "\nSession terminated, killing shell...");
		kill(ctl.child, SIGTERM);
		sleep(2);
		kill(ctl.child, SIGKILL);
		fprintf(stderr, " ...killed.\n");
	}

done:
	ul_pty_cleanup(ctl.pty);
	logging_done(&ctl, NULL);

	if (!ctl.quiet)
		printf("Script done.\n");

	ul_free_pty(ctl.pty);

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
