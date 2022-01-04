#include <stdio.h>
#include <stdlib.h>
#include <pty.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <paths.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>

#include <cassert>

#include "utils.h"
#include "all-io.h"
#include "ttyutils.h"
#include "pty-session.h"
#include "debug.h"

Pty::Pty(bool is_stdin_tty, PtyCallback& callback)
	: callback{ callback },
	isterm{ is_stdin_tty },
	master{ -1 },
	slave{ -1 },
	sigfd{ -1 },
	child{ static_cast<pid_t>(-1) } {}

Pty::~Pty() {}

void ul_pty_slave_echo(Pty *pty, int enable) {
	assert(pty);
	pty->slave_echo = enable ? 1 : 0;
}

int ul_pty_get_delivered_signal(Pty *pty) {
	assert(pty);
	return pty->delivered_signal;
}

void ul_pty_set_child(Pty *pty, pid_t child) {
	assert(pty);
	pty->child = child;
}

int ul_pty_get_childfd(Pty *pty) {
	assert(pty);
	return pty->master;
}

pid_t ul_pty_get_child(Pty *pty) {
	assert(pty);
	return pty->child;
}

/* it's active when signals are redirected to sigfd */
int ul_pty_is_running(Pty *pty) {
	assert(pty);
	return pty->sigfd >= 0;
}

void ul_pty_set_mainloop_time(Pty *pty, struct timeval *tv) {
	assert(pty);
	if (!tv) {
		DBG(pty << ": mainloop time: clear");
		timerclear(&pty->next_callback_time);
	} else {
		pty->next_callback_time.tv_sec = tv->tv_sec;
		pty->next_callback_time.tv_usec = tv->tv_usec;
		DBG(pty << ": mainloop time: "<< (int64_t) tv->tv_sec << "." << (int64_t) tv->tv_usec);
	}
}

static void pty_signals_cleanup(Pty *pty) {
	if (pty->sigfd != -1)
		close(pty->sigfd);
	pty->sigfd = -1;

	/* restore original setting */
	sigprocmask(SIG_SETMASK, &pty->orgsig, nullptr);
}

/* call me before fork() */
int ul_pty_setup(Pty *pty) {
	struct termios attrs;
	sigset_t ourset;
	int rc = 0;

	assert(pty->sigfd == -1);

	/* save the current signals setting */
	sigprocmask(0, nullptr, &pty->orgsig);

	if (pty->isterm) {
		DBG(pty << ": create for terminal");

		/* original setting of the current terminal */
		if (tcgetattr(STDIN_FILENO, &pty->stdin_attrs) != 0) {
			rc = -errno;
			goto done;
		}

		attrs = pty->stdin_attrs;
		if (pty->slave_echo)
			attrs.c_lflag |= ECHO;
		else
			attrs.c_lflag &= ~ECHO;

		ioctl(STDIN_FILENO, TIOCGWINSZ, (char *)&pty->win);
		/* create master+slave */
		rc = openpty(&pty->master, &pty->slave, nullptr, &attrs, &pty->win);
		if (rc)
			goto done;

		/* set the current terminal to raw mode; pty_cleanup() reverses this change on exit */
		cfmakeraw(&attrs);
		tcsetattr(STDIN_FILENO, TCSANOW, &attrs);
	} else {
		DBG(pty << ": create for non-terminal");

		rc = openpty(&pty->master, &pty->slave, nullptr, nullptr, nullptr);
		if (rc)
			goto done;

		tcgetattr(pty->slave, &attrs);

		if (pty->slave_echo)
			attrs.c_lflag |= ECHO;
		else
			attrs.c_lflag &= ~ECHO;

		tcsetattr(pty->slave, TCSANOW, &attrs);
	}

	sigfillset(&ourset);
	if (sigprocmask(SIG_BLOCK, &ourset, nullptr)) {
		rc = -errno;
		goto done;
	}

	sigemptyset(&ourset);
	sigaddset(&ourset, SIGCHLD);
	sigaddset(&ourset, SIGWINCH);
	sigaddset(&ourset, SIGALRM);
	sigaddset(&ourset, SIGTERM);
	sigaddset(&ourset, SIGINT);
	sigaddset(&ourset, SIGQUIT);

	if (pty->callback.flushLogs())
		sigaddset(&ourset, SIGUSR1);

	if ((pty->sigfd = signalfd(-1, &ourset, SFD_CLOEXEC)) < 0)
		rc = -errno;
done:
	if (rc)
		ul_pty_cleanup(pty);

	DBG(pty << ": pty setup done [master=" << pty->master << ", slave=" << pty->slave << ", rc=" << rc << "]");
	return rc;
}

/* cleanup in parent process */
void ul_pty_cleanup(Pty *pty) {
	struct termios rtt;

	pty_signals_cleanup(pty);

	if (pty->master == -1 || !pty->isterm)
		return;

	DBG(pty << ": cleanup");
	rtt = pty->stdin_attrs;
	tcsetattr(STDIN_FILENO, TCSADRAIN, &rtt);
}

int ul_pty_chownmod_slave(Pty *pty, uid_t uid, gid_t gid, mode_t mode) {
	if (fchown(pty->slave, uid, gid))
		return -errno;
	if (fchmod(pty->slave, mode))
		return -errno;
	return 0;
}

/* call me in child process */
void ul_pty_init_slave(Pty *pty) {
	DBG(pty << ": initialize slave");

	setsid();

	ioctl(pty->slave, TIOCSCTTY, 1);
	close(pty->master);

	dup2(pty->slave, STDIN_FILENO);
	dup2(pty->slave, STDOUT_FILENO);
	dup2(pty->slave, STDERR_FILENO);

	close(pty->slave);

	if (pty->sigfd >= 0)
		close(pty->sigfd);

	pty->slave = -1;
	pty->master = -1;
	pty->sigfd = -1;

	sigprocmask(SIG_SETMASK, &pty->orgsig, nullptr);

	DBG(pty << ": initialize slave done");
}

static int write_output(char *obuf, ssize_t bytes) {
	DBG(" writing output");

	if (write_all(STDOUT_FILENO, obuf, bytes)) {
		DBG("  writing output *failed*");
		return -errno;
	}

	return 0;
}

static int write_to_child(Pty *pty, char *buf, size_t bufsz) {
	return write_all(pty->master, buf, bufsz);
}

/*
 * The pty is usually faster than shell, so it's a good idea to wait until
 * the previous message has been already read by shell from slave before we
 * write to master. This is necessary especially for EOF situation when we can
 * send EOF to master before shell is fully initialized, to workaround this
 * problem we wait until slave is empty. For example:
 *
 *   echo "date" | su --pty
 *
 * Unfortunately, the child (usually shell) can ignore stdin at all, so we
 * don't wait forever to avoid dead locks...
 *
 * Note that su --pty is primarily designed for interactive sessions as it
 * maintains master+slave tty stuff within the session. Use pipe to write to
 * pty and assume non-interactive (tee-like) behavior is NOT well supported.
 */
void ul_pty_write_eof_to_child(Pty *pty) {
	unsigned int tries = 0;
	struct pollfd fds[] = {
	           { .fd = pty->slave, .events = POLLIN }
	};
	char c = DEF_EOF;

	DBG(pty << ": waiting for empty slave");
	while (poll(fds, 1, 10) == 1 && tries < 8) {
		DBG(pty << ": slave is not empty");
		xusleep(250000);
		tries++;
	}
	if (tries < 8)
		DBG(pty << ": slave is empty now");

	DBG(pty << ": sending EOF to master");
	write_to_child(pty, &c, sizeof(char));
}

static int mainloop_callback(Pty *pty) {
	if (!pty->callback.useMainLoop()) {
		return 0;
	}

	DBG(pty << ": calling mainloop callback");
	int rc = pty->callback.mainLoop();

	DBG(pty << ": callback done [rc=" << rc << "]");
	return rc;
}

static int handle_io(Pty *pty, int fd, int *eof) {
	char buf[BUFSIZ];
	ssize_t bytes;
	sigset_t set;

	DBG(pty << ": handle I/O on fd=" << fd);
	*eof = 0;

	sigemptyset(&set);
	sigaddset(&set, SIGTTIN);
	sigprocmask(SIG_UNBLOCK, &set, nullptr);
	/* read from active FD */
	bytes = read(fd, buf, sizeof(buf));
	sigprocmask(SIG_BLOCK, &set, nullptr);
	if (bytes < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		return -errno;
	}

	if (bytes == 0) {
		*eof = 1;
		return 0;
	}

	/* from stdin (user) to command */
	if (fd == STDIN_FILENO) {
		DBG(pty << ": stdin --> master " << bytes << " bytes");

		if (write_to_child(pty, buf, bytes))
			return -errno;

		/* without sync write_output() will write both input &
		 * shell output that looks like double echoing */
		fdatasync(pty->master);

	/* from command (master) to stdout */
	} else if (fd == pty->master) {
		DBG(pty << ": master --> stdout " << bytes << " bytes");
		write_output(buf, bytes);
	}

	return pty->callback.logStreamActivity(fd, buf, bytes);
}

void ul_pty_wait_for_child(Pty *pty) {
	int status;
	pid_t pid;
	int options = 0;

	if (pty->child == (pid_t) -1)
		return;

	DBG("waiting for child [child=" << pty->child << "]");

	if (ul_pty_is_running(pty)) {
		/* wait for specific child */
		options = WNOHANG;
		for (;;) {
			pid = waitpid(pty->child, &status, options);
			DBG(" waitpid done [rc=" << pid << "]");
			if (pid != (pid_t) - 1) {
				pty->callback.childDie(pty->child, status);
				ul_pty_set_child(pty, (pid_t) -1);
			} else {
				break;
			}
		}
	} else {
		/* final wait */
		while ((pid = waitpid(-1, &status, options)) > 0) {
			DBG("waitpid done [rc=" << pid << "]");
			if (pid == pty->child) {
				pty->callback.childDie(pty->child, status);
				ul_pty_set_child(pty, (pid_t) -1);
			}
		}
	}
}

static int handle_signal(Pty *pty, int fd) {
	struct signalfd_siginfo info;
	ssize_t bytes;
	int rc = 0;

	DBG(pty << ": handle signal on fd=" << fd);

	bytes = read(fd, &info, sizeof(info));
	if (bytes != sizeof(info)) {
		if (bytes < 0 && (errno == EAGAIN || errno == EINTR))
			return 0;
		return -errno;
	}

	switch (info.ssi_signo) {
	case SIGCHLD:
		DBG(pty << ": get signal SIGCHLD");

		if (info.ssi_code == CLD_EXITED || info.ssi_code == CLD_KILLED || info.ssi_code == CLD_DUMPED) {
			if (pty->callback.useChildWait()) {
				pty->callback.childWait(pty->child);
			} else {
				ul_pty_wait_for_child(pty);
			}
		} else if (info.ssi_status == SIGSTOP && pty->child > 0) {
			pty->callback.childSigstop(pty->child);
		}

		if (pty->child <= 0) {
			DBG(pty << ": no child, setting leaving timeout");
			pty->poll_timeout = 10;
			timerclear(&pty->next_callback_time);
		}
		return 0;
	case SIGWINCH:
		DBG(pty << ": get signal SIGWINCH");
		if (pty->isterm) {
			ioctl(STDIN_FILENO, TIOCGWINSZ, (char *)&pty->win);
			ioctl(pty->slave, TIOCSWINSZ, (char *)&pty->win);
			rc = pty->callback.logSignal(&info, static_cast<void*>(&pty->win));
		}
		break;
	case SIGTERM:
		/* fallthrough */
	case SIGINT:
		/* fallthrough */
	case SIGQUIT:
		DBG(pty << ": get signal SIG{TERM,INT,QUIT}");
		pty->delivered_signal = info.ssi_signo;
		/* Child termination is going to generate SIGCHLD (see above) */
		if (pty->child > 0)
			kill(pty->child, SIGTERM);
			rc = pty->callback.logSignal(&info, static_cast<void*>(&pty->win));
		break;
	case SIGUSR1:
		DBG(pty << ": get signal SIGUSR1");
		rc = pty->callback.flushLogs();
		break;
	default:
		abort();
	}

	return rc;
}

/* loop in parent */
int ul_pty_proxy_master(Pty *pty) {
	int rc = 0, ret, eof = 0;
	enum {
		POLLFD_SIGNAL = 0,
		POLLFD_MASTER,
		POLLFD_STDIN

	};
	struct pollfd pfd[] = {
		[POLLFD_SIGNAL] = { .fd = -1,		.events = POLLIN | POLLERR | POLLHUP },
		[POLLFD_MASTER] = { .fd = pty->master,  .events = POLLIN | POLLERR | POLLHUP },
		[POLLFD_STDIN]	= { .fd = STDIN_FILENO, .events = POLLIN | POLLERR | POLLHUP }
	};

	/* We use signalfd, and standard signals by handlers are completely blocked */
	assert(pty->sigfd >= 0);

	pfd[POLLFD_SIGNAL].fd = pty->sigfd;
	pty->poll_timeout = -1;

	while (!pty->delivered_signal) {
		size_t i;
		int errsv, timeout;

		DBG(pty << ": --poll() loop--");

		/* note, callback usually updates @next_callback_time */
		if (timerisset(&pty->next_callback_time)) {
			struct timeval now;

			DBG(pty << ": callback requested");
			gettime_monotonic(&now);
			if (timercmp(&now, &pty->next_callback_time, >)) {
				rc = mainloop_callback(pty);
				if (rc)
					break;
			}
		}

		/* set timeout */
		if (timerisset(&pty->next_callback_time)) {
			struct timeval now, rest;

			gettime_monotonic(&now);
			timersub(&pty->next_callback_time, &now, &rest);
			timeout = (rest.tv_sec * 1000) +  (rest.tv_usec / 1000);
		} else
			timeout = pty->poll_timeout;

		/* wait for input, signal or timeout */
		DBG(pty << ": calling poll() [timeout=" << timeout << "ms]");
		ret = poll(pfd, ARRAY_SIZE(pfd), timeout);

		errsv = errno;
		DBG(pty << ": poll() rc=" << ret);

		/* error */
		if (ret < 0) {
			if (errsv == EAGAIN)
				continue;
			rc = -errno;
			break;
		}

		/* timeout */
		if (ret == 0) {
			if (timerisset(&pty->next_callback_time)) {
				rc = mainloop_callback(pty);
				if (rc == 0)
					continue;
			} else {
				rc = 0;
			}

			DBG(pty << ": leaving poll() loop [timeout=" << timeout << ", rc=" << rc << "]");
			break;
		}
		/* event */
		for (i = 0; i < ARRAY_SIZE(pfd); i++) {
			if (pfd[i].revents == 0)
				continue;

			// DBG(IO, ul_debugobj(pty, " active pfd[%s].fd=%d %s %s %s %s",
			// 			i == POLLFD_STDIN  ? "stdin" :
			// 			i == POLLFD_MASTER ? "master" :
			// 			i == POLLFD_SIGNAL ? "signal" : "???",
			// 			pfd[i].fd,
			// 			pfd[i].revents & POLLIN  ? "POLLIN" : "",
			// 			pfd[i].revents & POLLHUP ? "POLLHUP" : "",
			// 			pfd[i].revents & POLLERR ? "POLLERR" : "",
			// 			pfd[i].revents & POLLNVAL ? "POLLNVAL" : ""));

			if (i == POLLFD_SIGNAL)
				rc = handle_signal(pty, pfd[i].fd);
			else if (pfd[i].revents & POLLIN)
				rc = handle_io(pty, pfd[i].fd, &eof); /* data */

			if (rc) {
				ul_pty_write_eof_to_child(pty);
				break;
			}

			if (i == POLLFD_SIGNAL)
				continue;

			/* EOF maybe detected in two ways; they are as follows:
			 *	A) poll() return POLLHUP event after close()
			 *	B) read() returns 0 (no data)
			 *
			 * POLLNVAL means that fd is closed.
			 */
			if ((pfd[i].revents & POLLHUP) || (pfd[i].revents & POLLNVAL) || eof) {
				DBG(pty << ": ignore FD");
				pfd[i].fd = -1;
				if (i == POLLFD_STDIN) {
					ul_pty_write_eof_to_child(pty);
					DBG(pty << ": ignore STDIN");
				}
			}
		}
		if (rc)
			break;
	}

	if (rc && pty->child && pty->child != (pid_t) -1 && !pty->delivered_signal) {
		kill(pty->child, SIGTERM);
		sleep(2);
		kill(pty->child, SIGKILL);
	}

	pty_signals_cleanup(pty);

	DBG("poll() done [signal=" << pty->delivered_signal << ", rc=" << rc << "]");
	return rc;
}

#ifdef TEST_PROGRAM_PTY
/*
 * $ make test_pty
 * $ ./test_pty
 *
 * ... and see for example tty(1) or "ps afu"
 */
static void child_sigstop(void *data __attribute__((__unused__)), pid_t child)
{
	kill(getpid(), SIGSTOP);
	kill(child, SIGCONT);
}

int main(int argc, char *argv[])
{
	struct ul_pty_callbacks *cb;
	const char *shell, *command = nullptr, *shname = nullptr;
	int caught_signal = 0;
	pid_t child;
	struct Pty *pty;

	shell = getenv("SHELL");
	if (shell == nullptr)
		shell = _PATH_BSHELL;
	if (argc == 2)
		command = argv[1];

	pty = ul_new_pty(isatty(STDIN_FILENO));
	if (!pty)
		err(EXIT_FAILURE, "failed to allocate PTY handler");

	cb = ul_pty_get_callbacks(pty);
	cb->child_sigstop = child_sigstop;

	if (ul_pty_setup(pty))
		err(EXIT_FAILURE, "failed to create pseudo-terminal");

	fflush(stdout);			/* ??? */

	switch ((int) (child = fork())) {
	case -1: /* error */
		ul_pty_cleanup(pty);
		err(EXIT_FAILURE, "cannot create child process");
		break;

	case 0: /* child */
		ul_pty_init_slave(pty);

		signal(SIGTERM, SIG_DFL); /* because /etc/csh.login */

		shname = strrchr(shell, '/');
		shname = shname ? shname + 1 : shell;

		if (command)
			execl(shell, shname, "-c", command, (char *)nullptr);
		else
			execl(shell, shname, "-i", (char *)nullptr);
		err(EXIT_FAILURE, "failed to execute %s", shell);
		break;

	default:
		break;
	}

	/* parent */
	ul_pty_set_child(pty, child);

	/* this is the main loop */
	ul_pty_proxy_master(pty);

	/* all done; cleanup and kill */
	caught_signal = ul_pty_get_delivered_signal(pty);

	if (!caught_signal && ul_pty_get_child(pty) != (pid_t)-1)
		ul_pty_wait_for_child(pty);	/* final wait */

	if (caught_signal && ul_pty_get_child(pty) != (pid_t)-1) {
		fprintf(stderr, "\nSession terminated, killing shell...");
		kill(child, SIGTERM);
		sleep(2);
		kill(child, SIGKILL);
		fprintf(stderr, " ...killed.\n");
	}

	ul_pty_cleanup(pty);
	ul_free_pty(pty);
	return EXIT_SUCCESS;
}

#endif /* TEST_PROGRAM */
