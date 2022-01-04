/*
 * Copyright (C) 1980      Regents of the University of California.
 * Copyright (C) 2013-2019 Karel Zak <kzak@redhat.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "script.h"

#include <stdio.h>
#include <stdlib.h>
#include <paths.h>
#include <time.h>
#include <sys/stat.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <stddef.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <inttypes.h>
#include <err.h>

#include <string>
#include <vector>
#include <ctime>
#include <cassert>

#include "utils.h"
#include "closestream.h"
#include "ttyutils.h"
#include "all-io.h"
#include "monotonic.h"
#include "optutils.h"
#include "signames.h"
#include "pty-session.h"
#include "debug.h"

auto constexpr SCRIPT_DEBUG_INIT   = (1 << 1);
auto constexpr SCRIPT_DEBUG_PTY    = (1 << 2);
auto constexpr SCRIPT_DEBUG_IO     = (1 << 3);
auto constexpr SCRIPT_DEBUG_SIGNAL = (1 << 4);
auto constexpr SCRIPT_DEBUG_MISC   = (1 << 5);
auto constexpr SCRIPT_DEBUG_ALL    = 0xFFFF;

static UL_DEBUG_DEFINE_MASK(script);
UL_DEBUG_DEFINE_MASKNAMES(script) = UL_DEBUG_EMPTY_MASKNAMES;

#define DBG(m, x)    __UL_DBG(script, SCRIPT_DEBUG_, m, x)
#define ON_DBG(m, x) __UL_DBG_CALL(script, SCRIPT_DEBUG_, m, x)

auto constexpr FORMAT_TIMESTAMP_MAX = ((4*4+1)+11+9+4+1); // weekdays can be unicode

/*
 * Script is driven by stream (stdout/stdin) activity. It's possible to
 * associate arbitrary number of log files with the stream. We have two basic
 * types of log files: "timing file" (simple or multistream) and "data file"
 * (raw).
 *
 * The same log file maybe be shared between both streams. For example
 * multi-stream timing file is possible to use for stdin as well as for stdout.
 */

void init_terminal_info(ScriptControl *ctl) {
	if (ctl->ttyname || !ctl->isterm)
		return; // already initialized

	get_terminal_dimension(&ctl->ttycols, &ctl->ttylines);
	get_terminal_name(&ctl->ttyname, NULL, NULL);
	get_terminal_type(&ctl->ttytype);
}

ScriptLog *get_log_by_name(ScriptStream *stream, const std::string& name)
{
	size_t i;

	for (i = 0; i < stream->nlogs; i++) {
		ScriptLog* log = stream->logs[i];
		if (log->filename == name) {
			return log;
		}
	}
	return nullptr;
}

ScriptLog *log_associate(ScriptControl *ctl, ScriptStream *stream, const std::string& filename, ScriptFormat format) {
	ScriptLog *log;

	DBG(MISC, ul_debug("associate %s with stream", filename.c_str()));

	assert(ctl);
	assert(stream);

	log = get_log_by_name(stream, filename);
	if (log)
		return log;	/* already defined */

	log = get_log_by_name(stream == &ctl->out ? &ctl->in : &ctl->out, filename);
	if (!log) {
		// create a new log
		log = new ScriptLog();
		log->filename = filename;
		log->format = format;
	}

	// add log to the stream
	stream->logs.push_back(log);
	stream->nlogs++;

	// remember where to write info about signals
	if (format == ScriptFormat::TimingMulti) {
		if (!ctl->siglog) {
			ctl->siglog = log;
		}
		if (!ctl->infolog) {
			ctl->infolog = log;
		}
	}

	return log;
}

int log_close(ScriptControl *ctl, ScriptLog *log, const char *msg, int status) {
	int rc = 0;

	if (!log || !log->initialized)
		return 0;

	DBG(MISC, ul_debug("closing %s", log->filename.c_str()));

	switch (log->format) {
	case ScriptFormat::Raw:
	{
		char buf[FORMAT_TIMESTAMP_MAX];
		time_t tvec = std::time(nullptr);
		std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&tvec));

		if (msg)
			fprintf(log->fp, "\nScript done on %s [<%s>]\n", buf, msg);
		else
			fprintf(log->fp, "\nScript done on %s [COMMAND_EXIT_CODE=\"%d\"]\n", buf, status);
		break;
	}
	case ScriptFormat::TimingMulti:
	{
		struct timeval now = { 0 }, delta = { 0 };

		gettime_monotonic(&now);
		timersub(&now, &log->starttime, &delta);

		log_info(ctl, "DURATION", "%ld.%06ld",
			(int64_t)delta.tv_sec,
			(int64_t)delta.tv_usec);
		log_info(ctl, "EXIT_CODE", "%d", status);
		break;
	}
	case ScriptFormat::TimingSimple:
		break;
	}

	if (close_stream(log->fp) != 0) {
		warn("write failed: %s", log->filename.c_str());
		rc = -errno;
	}

	memset(log, 0, sizeof(*log));

	return rc;
}

static int log_flush(ScriptControl *ctl __attribute__((__unused__)), ScriptLog *log) {
	if (!log || !log->initialized)
		return 0;

	DBG(MISC, ul_debug("flushing %s", log->filename.c_str()));

	fflush(log->fp);
	return 0;
}

static void log_free(ScriptControl *ctl, ScriptLog *log) {
	size_t i;

	if (!log)
		return;

	/* the same log is possible to reference from more places, remove all
	 * (TODO: maybe use include/list.h to make it more elegant)
	 */
	if (ctl->siglog == log)
		ctl->siglog = NULL;
	else if (ctl->infolog == log)
		ctl->infolog = NULL;

	for (i = 0; i < ctl->out.nlogs; i++) {
		if (ctl->out.logs[i] == log)
			ctl->out.logs[i] = NULL;
	}
	for (i = 0; i < ctl->in.nlogs; i++) {
		if (ctl->in.logs[i] == log)
			ctl->in.logs[i] = NULL;
	}
	free(log);
}

static int log_start(ScriptControl *ctl, ScriptLog *log) {
	if (log->initialized)
		return 0;

	DBG(MISC, ul_debug("opening %s", log->filename.c_str()));

	assert(log->fp == NULL);

	/* open the log */
	log->fp = fopen(log->filename.c_str(),
			ctl->append && log->format == ScriptFormat::Raw ?
			"a" UL_CLOEXECSTR :
			"w" UL_CLOEXECSTR);
	if (!log->fp) {
		warn("cannot open %s", log->filename.c_str());
		return -errno;
	}

	/* write header, etc. */
	switch (log->format) {
	case ScriptFormat::Raw:
	{
		char buf[FORMAT_TIMESTAMP_MAX];
		time_t tvec = std::time(nullptr);
		std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&tvec));

		fprintf(log->fp, "Script started on %s [", buf);

		if (ctl->isterm) {
			init_terminal_info(ctl);

			if (ctl->ttytype)
				fprintf(log->fp, "TERM=\"%s\" ", ctl->ttytype);
			if (ctl->ttyname)
				fprintf(log->fp, "TTY=\"%s\" ", ctl->ttyname);

			fprintf(log->fp, "COLUMNS=\"%d\" LINES=\"%d\"", ctl->ttycols, ctl->ttylines);
		} else
			fprintf(log->fp, "<not executed on terminal>");

		fputs("]\n", log->fp);
		break;
	}
	case ScriptFormat::TimingSimple:
	case ScriptFormat::TimingMulti:
		gettime_monotonic(&log->oldtime);
		gettime_monotonic(&log->starttime);
		break;
	}

	log->initialized = 1;
	return 0;
}

int logging_start(ScriptControl *ctl) {
	size_t i;

	/* start all output logs */
	for (i = 0; i < ctl->out.nlogs; i++) {
		int rc = log_start(ctl, ctl->out.logs[i]);
		if (rc)
			return rc;
	}

	/* start all input logs */
	for (i = 0; i < ctl->in.nlogs; i++) {
		int rc = log_start(ctl, ctl->in.logs[i]);
		if (rc)
			return rc;
	}
	return 0;
}

static ssize_t log_write(ScriptControl *ctl,
		      ScriptStream *stream,
		      ScriptLog *log,
		      char *obuf, size_t bytes)
{
	int rc;
	ssize_t ssz = 0;
	struct timeval now, delta;

	if (!log->fp)
		return 0;

	DBG(IO, ul_debug(" writing [file=%s]", log->filename.c_str()));

	switch (log->format) {
	case ScriptFormat::Raw:
		DBG(IO, ul_debug("  log raw data"));

		// printf("\n\nraw data: %s\n\n", obuf);

		rc = fwrite_all(obuf, 1, bytes, log->fp);
		if (rc) {
			warn("cannot write %s", log->filename.c_str());
			return rc;
		}
		ssz = bytes;
		break;

	case ScriptFormat::TimingSimple:
		DBG(IO, ul_debug("  log timing info"));

		gettime_monotonic(&now);
		timersub(&now, &log->oldtime, &delta);
		ssz = fprintf(log->fp, "%ld.%06ld %zd\n",
			(int64_t)delta.tv_sec, (int64_t)delta.tv_usec, bytes);
		if (ssz < 0)
			return -errno;

		log->oldtime = now;
		break;

	case ScriptFormat::TimingMulti:
		DBG(IO, ul_debug("  log multi-stream timing info"));

		gettime_monotonic(&now);
		timersub(&now, &log->oldtime, &delta);
		ssz = fprintf(log->fp, "%c %ld.%06ld %zd\n",
			stream->ident,
			(int64_t)delta.tv_sec, (int64_t)delta.tv_usec, bytes);
		if (ssz < 0)
			return -errno;

		log->oldtime = now;
		break;
	default:
		break;
	}

	if (ctl->flush)
		fflush(log->fp);
	return ssz;
}

static ssize_t log_stream_activity(
			ScriptControl *ctl,
			ScriptStream *stream,
			char *buf, size_t bytes)
{
	size_t i;
	ssize_t outsz = 0;

	for (i = 0; i < stream->nlogs; i++) {
		ssize_t ssz = log_write(ctl, stream, stream->logs[i], buf, bytes);

		if (ssz < 0)
			return ssz;
		outsz += ssz;
	}

	return outsz;
}

static ssize_t __attribute__ ((__format__ (__printf__, 3, 4)))
	log_signal(ScriptControl *ctl, int signum, const char *msgfmt, ...)
{
	ScriptLog *log;
	struct timeval now, delta;
	char msg[BUFSIZ] = {0};
	va_list ap;
	ssize_t sz;

	assert(ctl);

	log = ctl->siglog;
	if (!log)
		return 0;

	assert(log->format == ScriptFormat::TimingMulti);
	DBG(IO, ul_debug("  writing signal to multi-stream timing"));

	gettime_monotonic(&now);
	timersub(&now, &log->oldtime, &delta);

	if (msgfmt) {
		int rc;
		va_start(ap, msgfmt);
		rc = vsnprintf(msg, sizeof(msg), msgfmt, ap);
		va_end(ap);
		if (rc < 0)
			*msg = '\0';;
	}

	if (*msg)
		sz = fprintf(log->fp, "S %ld.%06ld SIG%s %s\n",
			(int64_t)delta.tv_sec, (int64_t)delta.tv_usec,
			signum_to_signame(signum), msg);
	else
		sz = fprintf(log->fp, "S %ld.%06ld SIG%s\n",
			(int64_t)delta.tv_sec, (int64_t)delta.tv_usec,
			signum_to_signame(signum));

	log->oldtime = now;
	return sz;
}

ssize_t log_info(ScriptControl *ctl, const char *name, const char *msgfmt, ...) {
	ScriptLog *log;
	char msg[BUFSIZ] = {0};
	va_list ap;
	ssize_t sz;

	assert(ctl);

	log = ctl->infolog;
	if (!log)
		return 0;

	assert(log->format == ScriptFormat::TimingMulti);
	DBG(IO, ul_debug("  writing info to multi-stream log"));

	if (msgfmt) {
		int rc;
		va_start(ap, msgfmt);
		rc = vsnprintf(msg, sizeof(msg), msgfmt, ap);
		va_end(ap);
		if (rc < 0)
			*msg = '\0';;
	}

	if (*msg)
		sz = fprintf(log->fp, "H %f %s %s\n", 0.0, name, msg);
	else
		sz = fprintf(log->fp, "H %f %s\n", 0.0, name);

	return sz;
}


void logging_done(ScriptControl *ctl, const char *msg) {
	int status;
	size_t i;

	DBG(MISC, ul_debug("stop logging"));

	if (WIFSIGNALED(ctl->childstatus))
		status = WTERMSIG(ctl->childstatus) + 0x80;
	else
		status = WEXITSTATUS(ctl->childstatus);

	DBG(MISC, ul_debug(" status=%d", status));

	/* close all output logs */
	for (i = 0; i < ctl->out.nlogs; i++) {
		ScriptLog *log = ctl->out.logs[i];
		log_close(ctl, log, msg, status);
		log_free(ctl, log);
	}
	for (auto log : ctl->out.logs) {
		delete log;
	}
	ctl->out.logs.clear();
	ctl->out.nlogs = 0;

	/* close all input logs */
	for (i = 0; i < ctl->in.nlogs; i++) {
		ScriptLog *log = ctl->in.logs[i];
		log_close(ctl, log, msg, status);
		log_free(ctl, log);
	}
	for (auto log : ctl->in.logs) {
		delete log;
	}
	ctl->in.logs.clear();
	ctl->in.nlogs = 0;
}

void callback_child_die(void* data, pid_t child, int status) {
	ScriptControl *ctl = (ScriptControl *) data;

	ctl->child = (pid_t) -1;
	ctl->childstatus = status;
}

void callback_child_sigstop(void* data, pid_t child) {
	DBG(SIGNAL, ul_debug(" child stop by SIGSTOP -- stop parent too"));
	kill(getpid(), SIGSTOP);
	DBG(SIGNAL, ul_debug(" resume"));
	kill(child, SIGCONT);
}

int callback_log_stream_activity(void* data, int fd, char* buf, size_t bufsz) {
	ScriptControl *ctl = (ScriptControl *) data;
	ssize_t ssz = 0;

	DBG(IO, ul_debug("stream activity callback"));

	/* from stdin (user) to command */
	if (fd == STDIN_FILENO)
		ssz = log_stream_activity(ctl, &ctl->in, buf, (size_t) bufsz);

	/* from command (master) to stdout and log */
	else if (fd == ul_pty_get_childfd(ctl->pty))
		ssz = log_stream_activity(ctl, &ctl->out, buf, (size_t) bufsz);

	if (ssz < 0)
		return (int) ssz;

	DBG(IO, ul_debug(" append %ld bytes [summary=%zu, max=%zu]", ssz,
				ctl->outsz, ctl->maxsz));

	ctl->outsz += ssz;

	/* check output limit */
	if (ctl->maxsz != 0 && ctl->outsz >= ctl->maxsz) {
		if (!ctl->quiet)
			printf("Script terminated, max output files size %lu exceeded.\n", ctl->maxsz);
		DBG(IO, ul_debug("output size %lu, exceeded limit %lu", ctl->outsz, ctl->maxsz));
		logging_done(ctl, "max output size exceeded");
		return 1;
	}
	return 0;
}

int callback_log_signal(void* data, struct signalfd_siginfo* info, void* sigdata) {
	ScriptControl *ctl = (ScriptControl *) data;
	ssize_t ssz = 0;

	switch (info->ssi_signo) {
	case SIGWINCH:
	{
		struct winsize *win = (struct winsize *) sigdata;
		ssz = log_signal(ctl, info->ssi_signo, "ROWS=%d COLS=%d",
					win->ws_row, win->ws_col);
		break;
	}
	case SIGTERM:
		/* fallthrough */
	case SIGINT:
		/* fallthrough */
	case SIGQUIT:
		ssz = log_signal(ctl, info->ssi_signo, NULL);
		break;
	default:
		/* no log */
		break;
	}

	return ssz < 0 ? ssz : 0;
}

int callback_flush_logs(void* data) {
	ScriptControl* ctl = (ScriptControl *) data;
	size_t i;

	for (i = 0; i < ctl->out.nlogs; i++) {
		int rc = log_flush(ctl, ctl->out.logs[i]);
		if (rc)
			return rc;
	}

	for (i = 0; i < ctl->in.nlogs; i++) {
		int rc = log_flush(ctl, ctl->in.logs[i]);
		if (rc)
			return rc;
	}
	return 0;
}
