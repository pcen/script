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

#include <sys/signalfd.h>

class PtyCallback {
public:
	virtual ~PtyCallback() {}

	/*
	 * Optional. Executed on SIGCHLD when ssi_code is EXITED, KILLED or
	 * DUMPED; The callback has to call ul_pty_set_child(pty, (pid_t) -1)
	 * if child is no longer alive.
	 */
	virtual bool ptyUseChildWait() { return false; }
	virtual void ptyChildWait(pid_t) {}

	/*
	 * Used when useChildWait() is false to inform about child status
	 */
	virtual void ptyChildDie(pid_t, int) = 0;

	/*
	 * Executed on SIGCHLD when ssi_status is SIGSTOP
	 */
	virtual void ptyChildSigstop(pid_t) = 0;

	/*
	 * Executed in master loop before Pty enter poll() and in time set by
	 * ul_pty_set_mainloop_time(). The callback is no used when time is not set.
	 */
	virtual bool ptyUseMainLoop() { return false; }
	virtual int ptyMainLoop() { return 0; };

	/*
	 * Executed on master or stdin activity, arguments:
	 *   2nd - file descriptor
	 *   3rd - buffer with data
	 *   4th - size of the data
	 */
	virtual int ptyLogStreamActivity(int, char*, size_t) = 0;

	/*
	 * Executed on signal, arguments:
	 *   2nd - signal info
	 *   3rd - NULL or signal specific data (e.g. struct winsize on SIGWINCH)
	 */
	virtual int ptyLogSignal(struct signalfd_siginfo*, void*) = 0;

	/*
	 * Executed on SIGUSR1
	 */
	virtual int ptyFlushLogs() = 0;
};

struct Pty {
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

	Pty(bool is_stdin_tty, PtyCallback& callback);
	~Pty();
};

void ul_pty_slave_echo(Pty *pty, int enable);
int ul_pty_get_delivered_signal(Pty *pty);

void ul_pty_set_child(Pty *pty, pid_t child);

int ul_pty_is_running(Pty *pty);
int ul_pty_setup(Pty *pty);
void ul_pty_cleanup(Pty *pty);
int ul_pty_chownmod_slave(Pty *pty, uid_t uid, gid_t gid, mode_t mode);
void ul_pty_init_slave(Pty *pty);
int ul_pty_proxy_master(Pty *pty);

void ul_pty_set_mainloop_time(Pty *pty, struct timeval *tv);
int ul_pty_get_childfd(Pty *pty);
void ul_pty_wait_for_child(Pty *pty);
pid_t ul_pty_get_child(Pty *pty);
void ul_pty_write_eof_to_child(Pty *pty);

#endif /* UTIL_LINUX_PTY_H */
