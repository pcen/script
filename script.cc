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
#include <stdarg.h>
#include <getopt.h>
#include <err.h>

#include <ctime>
#include <cassert>

#include "utils.h"
#include "closestream.h"
#include "ttyutils.h"
#include "all-io.h"
#include "optutils.h"
#include "signames.h"
#include "pty-session.h"
#include "debug.h"

auto constexpr FORMAT_TIMESTAMP_MAX = ((4*4+1)+11+9+4+1); // weekdays can be unicode

ScriptControl::ScriptControl()
	: outsz{ 0 },
	maxsz{ 0 },
	siglog{ nullptr },
	infolog{ nullptr },
	ttyname{ nullptr },
	ttytype{ nullptr },
	ttycols{ 0 },
	ttylines{ 0 },
	pty{ nullptr },
	childstatus{ 0 },
	append{ false },
	rc_wanted{ false },
	flush{ false },
	quiet{ false },
	force{ false },
	isterm{ false } {}

void ScriptControl::initTerminalInfo() {
	if (ttyname || !isterm) {
		return;
	}
	get_terminal_dimension(&ttycols, &ttylines);
	get_terminal_name(&ttyname, nullptr, nullptr);
	get_terminal_type(&ttytype);
}

ScriptStream::ScriptStream(char ident) : ident{ ident } {}

ScriptLog* ScriptStream::getLogByName(const std::string& name) {
	for (auto log : logs) {
		if (log->filename == name) return log;
	}
	return nullptr;
}

ScriptLog* ScriptControl::associate(ScriptStream* stream, const std::string& filename, ScriptFormat format) {
	DBG("associate" << filename << " with stream");

	assert(stream);

	ScriptLog* log = stream->getLogByName(filename);
	if (log) return log;

	log = stream == &out ? in.getLogByName(filename) : out.getLogByName(filename);
	if (!log) {
		log = new ScriptLog();
		log->filename = filename;
		log->format = format;
	}

	stream->logs.push_back(log);

	// remember where to write info about signals
	if (format == ScriptFormat::TimingMulti) {
		if (!siglog) {
			siglog = log;
		}
		if (!infolog) {
			infolog = log;
		}
	}

	return log;
}

int log_close(ScriptControl *ctl, ScriptLog *log, const char *msg, int status) {
	int rc = 0;

	if (!log || !log->initialized)
		return 0;

	DBG("closing " << log->filename);

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

	DBG("flushing " << log->filename);

	fflush(log->fp);
	return 0;
}

static void log_free(ScriptControl *ctl, ScriptLog *log) {
	size_t i;

	if (!log)
		return;

	if (ctl->siglog == log)
		ctl->siglog = nullptr;
	else if (ctl->infolog == log)
		ctl->infolog = nullptr;

	for (i = 0; i < ctl->out.logs.size(); i++) {
		if (ctl->out.logs[i] == log)
			ctl->out.logs[i] = nullptr;
	}
	for (i = 0; i < ctl->in.logs.size(); i++) {
		if (ctl->in.logs[i] == log)
			ctl->in.logs[i] = nullptr;
	}
	delete log;
}

static int log_start(ScriptControl *ctl, ScriptLog *log) {
	if (log->initialized)
		return 0;

	DBG("opening " << log->filename);

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
			ctl->initTerminalInfo();

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
	/* start all output logs */
	for (auto log : ctl->out.logs) {
		int rc = log_start(ctl, log);
		if (rc)
			return rc;
	}

	/* start all input logs */
	for (auto log : ctl->in.logs) {
		int rc = log_start(ctl, log);
		if (rc)
			return rc;
	}
	return 0;
}

ssize_t log_write(ScriptControl *ctl, ScriptStream *stream, ScriptLog *log, char *obuf, size_t bytes) {
	int rc;
	ssize_t ssz = 0;
	struct timeval now, delta;

	if (!log->fp)
		return 0;

	DBG(" writing [file=" << log->filename << "]");

	switch (log->format) {
	case ScriptFormat::Raw:
		DBG("  log raw data");

		rc = fwrite_all(obuf, 1, bytes, log->fp);
		if (rc) {
			warn("cannot write %s", log->filename.c_str());
			return rc;
		}
		ssz = bytes;
		break;

	case ScriptFormat::TimingSimple:
		DBG("  log timing info");

		gettime_monotonic(&now);
		timersub(&now, &log->oldtime, &delta);
		ssz = fprintf(log->fp, "%ld.%06ld %zd\n",
			(int64_t)delta.tv_sec, (int64_t)delta.tv_usec, bytes);
		if (ssz < 0)
			return -errno;

		log->oldtime = now;
		break;

	case ScriptFormat::TimingMulti:
		DBG("  log multi-stream timing info");

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

ssize_t log_stream_activity(ScriptControl* ctl, ScriptStream* stream, char* buf, size_t bytes) {
	ssize_t outsz = 0;
	for (auto log : stream->logs) {
		ssize_t ssz = log_write(ctl, stream, log, buf, bytes);

		if (ssz < 0)
			return ssz;
		outsz += ssz;
	}
	return outsz;
}

ssize_t  log_signal(ScriptControl *ctl, int signum, const char *msgfmt, ...) {
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
	DBG("  writing signal to multi-stream timing");

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
	DBG("  writing info to multi-stream log");

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

	DBG("stop logging");

	if (WIFSIGNALED(ctl->childstatus))
		status = WTERMSIG(ctl->childstatus) + 0x80;
	else
		status = WEXITSTATUS(ctl->childstatus);

	DBG(" status=" << status);

	/* close all output logs */
	for (auto log : ctl->out.logs) {
		log_close(ctl, log, msg, status);
		log_free(ctl, log);
	}
	for (auto log : ctl->out.logs) {
		delete log;
	}
	ctl->out.logs.clear();

	/* close all input logs */
	for (auto log : ctl->in.logs) {
		log_close(ctl, log, msg, status);
		log_free(ctl, log);
	}
	for (auto log : ctl->in.logs) {
		delete log;
	}
	ctl->in.logs.clear();
}

void callback_child_die(void* data, pid_t child, int status) {
	ScriptControl *ctl = (ScriptControl *) data;

	ctl->child = (pid_t) -1;
	ctl->childstatus = status;
}

void callback_child_sigstop(void* data, pid_t child) {
	DBG(" child stop by SIGSTOP -- stop parent too");
	kill(getpid(), SIGSTOP);
	DBG(" resume");
	kill(child, SIGCONT);
}

int callback_log_stream_activity(void* data, int fd, char* buf, size_t bufsz) {
	ScriptControl *ctl = (ScriptControl*) data;
	ssize_t ssz = 0;

	DBG("stream activity callback");

	/* from stdin (user) to command */
	if (fd == STDIN_FILENO)
		ssz = log_stream_activity(ctl, &ctl->in, buf, (size_t) bufsz);

	/* from command (master) to stdout and log */
	else if (fd == ul_pty_get_childfd(ctl->pty))
		ssz = log_stream_activity(ctl, &ctl->out, buf, (size_t) bufsz);

	if (ssz < 0)
		return (int) ssz;

	DBG(" append " << ssz << " bytes [summary=" << ctl->outsz << ", max=" << ctl->maxsz << "]");

	ctl->outsz += ssz;

	/* check output limit */
	if (ctl->maxsz != 0 && ctl->outsz >= ctl->maxsz) {
		if (!ctl->quiet)
			printf("Script terminated, max output files size %lu exceeded.\n", ctl->maxsz);
		DBG("output size " << ctl->outsz << ", exceeded limit " << ctl->maxsz);
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
		ssz = log_signal(ctl, info->ssi_signo, "ROWS=%d COLS=%d", win->ws_row, win->ws_col);
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

	for (auto log : ctl->out.logs) {
		int rc = log_flush(ctl, log);
		if (rc)
			return rc;
	}

	for (auto log : ctl->in.logs) {
		int rc = log_flush(ctl, log);
		if (rc)
			return rc;
	}
	return 0;
}
