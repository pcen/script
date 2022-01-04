/*
 * This code is in the public domain; do with it what you wish.
 *
 * Written by Karel Zak <kzak@redhat.com> in Jul 2019
 */
#ifndef UTIL_LINUX_PTY_SESSION_H
#define UTIL_LINUX_PTY_SESSION_H

#include <pty.h>
#include <termios.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <sys/signalfd.h>

class PtyCallback {
public:
	virtual ~PtyCallback() {}

	/*
	 * Optional. Executed on SIGCHLD when ssi_code is EXITED, KILLED or
	 * DUMPED; The callback has to call ul_pty_set_child(pty, (pid_t) -1)
	 * if child is no longer alive.
	 */
	virtual bool useChildWait() { return false; }
	virtual void childWait(pid_t) {}

	/*
	 * Used when useChildWait() is false to inform about child status
	 */
	virtual void childDie(pid_t, int) = 0;

	/*
	 * Executed on SIGCHLD when ssi_status is SIGSTOP
	 */
	virtual void childSigstop(pid_t) = 0;

	/*
	 * Executed in master loop before ul_pty enter poll() and in time set by
	 * ul_pty_set_mainloop_time(). The callback is no used when time is not set.
	 */
	virtual bool useMainLoop() { return false; }
	virtual int mainLoop() {};

	/*
	 * Executed on master or stdin activity, arguments:
	 *   2nd - file descriptor
	 *   3rd - buffer with data
	 *   4th - size of the data
	 */
	virtual int logStreamActivity(int, char*, size_t) = 0;

	/*
	 * Executed on signal, arguments:
	 *   2nd - signal info
	 *   3rd - NULL or signal specific data (e.g. struct winsize on SIGWINCH)
	 */
	virtual int logSignal(struct signalfd_siginfo*, void*) = 0;

	/*
	 * Executed on SIGUSR1
	 */
	virtual int flushLogs() = 0;
};

struct ul_pty {
	struct termios stdin_attrs; // stdin and slave terminal runtime attributes
	int master; // parent side
	int slave;  // child side
	int sigfd;  // signalfd()
	int poll_timeout;
	struct winsize win; // terminal window size
	sigset_t orgsig; // original signal mask

	int delivered_signal;

	PtyCallback& callback;

	pid_t child;

	struct timeval next_callback_time;

	bool isterm; // is stdin terminal?
	unsigned int slave_echo; // keep ECHO on pty slave

	ul_pty(bool is_stdin_tty, PtyCallback& callback);
	~ul_pty();

};

void ul_pty_slave_echo(struct ul_pty *pty, int enable);
int ul_pty_get_delivered_signal(struct ul_pty *pty);

void ul_pty_set_child(struct ul_pty *pty, pid_t child);

int ul_pty_is_running(struct ul_pty *pty);
int ul_pty_setup(struct ul_pty *pty);
void ul_pty_cleanup(struct ul_pty *pty);
int ul_pty_chownmod_slave(struct ul_pty *pty, uid_t uid, gid_t gid, mode_t mode);
void ul_pty_init_slave(struct ul_pty *pty);
int ul_pty_proxy_master(struct ul_pty *pty);

void ul_pty_set_mainloop_time(struct ul_pty *pty, struct timeval *tv);
int ul_pty_get_childfd(struct ul_pty *pty);
void ul_pty_wait_for_child(struct ul_pty *pty);
pid_t ul_pty_get_child(struct ul_pty *pty);
void ul_pty_write_eof_to_child(struct ul_pty *pty);

#endif /* UTIL_LINUX_PTY_H */
