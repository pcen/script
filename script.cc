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

#include <stdlib.h>
#include <stdarg.h>
#include <err.h>

#include <cstdio>
#include <ctime>
#include <cassert>

#include "utils.h"
#include "closestream.h"
#include "ttyutils.h"
#include "signames.h"
#include "debug.h"

auto constexpr FORMAT_TIMESTAMP_MAX = ((4*4+1)+11+9+4+1); // weekdays can be unicode

ScriptLog::ScriptLog(const std::string& filename, ScriptFormat format)
	: fp{ nullptr }, format{ format }, filename{ filename }, initialized{ false } {}

int ScriptLog::flush() {
	if (!initialized) {
		return 0;
	}
	DBG("flushing " << filename);

	return fflush(fp); // 0 on success
}

int ScriptLog::write(const std::string& str) {
	return fwrite(str.c_str(), sizeof(char), str.size(), fp) > 0 ? 0 : -1;
}

int ScriptLog::write(char* buf, size_t bytes) {
	const void* ptr = (const void*)buf;
	while (bytes) {
		size_t tmp;

		errno = 0;
		tmp = fwrite(ptr, 1, bytes, fp);
		if (tmp > 0) {
			bytes -= tmp;
			if (bytes) {
				ptr = static_cast<const void *>(static_cast<const char *>(ptr) + tmp);
			}
		} else if (errno != EINTR && errno != EAGAIN) {
			return -1;
		}
		if (errno == EAGAIN) {
			xusleep(250000);
		}
	}
	return 0;
}

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

bool ScriptStream::operator==(const ScriptStream& rhs) const {
	return this == &rhs;
}

ScriptLog* ScriptControl::associate(ScriptStream& stream, const std::string& filename, ScriptFormat format) {
	DBG("associate" << filename << " with stream");

	ScriptLog* log = stream.getLogByName(filename);
	if (log) {
		return log;
	}

	log = stream == out ? in.getLogByName(filename) : out.getLogByName(filename);
	if (!log) {
		log = new ScriptLog(filename, format);
	}

	stream.logs.push_back(log);

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

int ScriptControl::closeLog(ScriptLog *log, const char *msg, int status) {
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

		if (msg) {
			log->write("\nScript done on %s [<%s>]\n", buf, msg);
		} else {
			log->write("\nScript done on %s [COMMAND_EXIT_CODE=\"%d\"]\n", buf, status);
		}
		break;
	}
	case ScriptFormat::TimingMulti:
	{
		struct timeval now = { 0 }, delta = { 0 };

		gettime_monotonic(&now);
		timersub(&now, &log->starttime, &delta);

		logInfo("DURATION", "%ld.%06ld", (int64_t)delta.tv_sec, (int64_t)delta.tv_usec);
		logInfo("EXIT_CODE", "%d", status);
		break;
	}
	case ScriptFormat::TimingSimple:
		break;
	}

	if (close_stream(log->fp) != 0) {
		warn("write failed: %s", log->filename.c_str());
		rc = -errno;
	}

	return rc;
}

void ScriptControl::deleteLog(ScriptLog *log) {
	if (!log)
		return;

	if (siglog == log) {
		siglog = nullptr;
	} else if (infolog == log) {
		infolog = nullptr;
	}

	for (size_t i = 0; i < out.logs.size(); i++) {
		if (out.logs[i] == log) {
			out.logs[i] = nullptr;
		}
	}
	for (size_t i = 0; i < in.logs.size(); i++) {
		if (in.logs[i] == log) {
			in.logs[i] = nullptr;
		}
	}
	delete log;
}

int ScriptControl::startLog(ScriptLog *log) {
	if (log->initialized)
		return 0;

	DBG("opening " << log->filename);

	assert(log->fp == nullptr);

	// open the log
	log->fp = fopen(log->filename.c_str(), append && log->format == ScriptFormat::Raw ? "a" UL_CLOEXECSTR : "w" UL_CLOEXECSTR);
	if (!log->fp) {
		warn("cannot open %s", log->filename.c_str());
		return -errno;
	}

	// write header, etc.
	switch (log->format) {
	case ScriptFormat::Raw:
	{
		char buf[FORMAT_TIMESTAMP_MAX];
		time_t tvec = std::time(nullptr);
		std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&tvec));

		log->write("Script started on %s [", buf);

		if (isterm) {
			initTerminalInfo();

			if (ttytype) {
				log->write("TERM=\"%s\" ", ttytype);
			}
			if (ttyname) {
				log->write("TTY=\"%s\" ", ttyname);
			}
			log->write("COLUMNS=\"%d\" LINES=\"%d\"", ttycols, ttylines);
		} else {
			log->write("<not executed on terminal>");
		}
		log->write("]\n");
		break;
	}
	case ScriptFormat::TimingSimple:
	case ScriptFormat::TimingMulti:
		gettime_monotonic(&log->oldtime);
		gettime_monotonic(&log->starttime);
		break;
	}

	log->initialized = true;
	return 0;
}

int ScriptControl::loggingStart() {
	// start output logs
	for (auto log : out.logs) {
		int rc = startLog(log);
		if (rc) {
			return rc;
		}
	}

	// start input logs
	for (auto log : in.logs) {
		int rc = startLog(log);
		if (rc) {
			return rc;
		}
	}
	return 0;
}

ssize_t ScriptControl::logWrite(ScriptStream& stream, ScriptLog* log, char* obuf, size_t bytes) {
	int rc;
	ssize_t ssz = 0;
	struct timeval now, delta;

	if (!log->fp) {
		return 0;
	}

	DBG(" writing [file=" << log->filename << "]");

	switch (log->format) {
	case ScriptFormat::Raw:
		DBG("  log raw data");

		rc = log->write(obuf, bytes);
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
		ssz = log->write("%ld.%06ld %zd\n", (int64_t)delta.tv_sec, (int64_t)delta.tv_usec, bytes);
		if (ssz < 0) {
			return -errno;
		}

		log->oldtime = now;
		break;

	case ScriptFormat::TimingMulti:
		DBG("  log multi-stream timing info");

		gettime_monotonic(&now);
		timersub(&now, &log->oldtime, &delta);
		ssz = log->write("%c %ld.%06ld %zd\n", stream.ident, (int64_t)delta.tv_sec, (int64_t)delta.tv_usec, bytes);
		if (ssz < 0) {
			return -errno;
		}

		log->oldtime = now;
		break;
	default:
		break;
	}

	if (flush) {
		log->flush();
	}
	return ssz;
}

// logStreamActivity writes a message to the given script stream
ssize_t ScriptControl::logStreamActivity(ScriptStream& stream, char* buf, size_t bytes) {
	ssize_t outsz = 0;
	for (auto log : stream.logs) {
		ssize_t ssz = logWrite(stream, log, buf, bytes);
		if (ssz < 0) {
			return ssz;
		}
		outsz += ssz;
	}
	return outsz;
}

// logSignal writes a message to the siglog
ssize_t ScriptControl::logSignal(int signum, const char* msgfmt, ...) {
	struct timeval now, delta;
	char msg[BUFSIZ] = {0};
	va_list ap;
	ssize_t sz;

	ScriptLog* log = siglog;
	if (!log) {
		return 0;
	}

	assert(log->format == ScriptFormat::TimingMulti);
	DBG("  writing signal to multi-stream timing");

	gettime_monotonic(&now);
	timersub(&now, &log->oldtime, &delta);

	if (msgfmt) {
		int rc;
		va_start(ap, msgfmt);
		rc = vsnprintf(msg, sizeof(msg), msgfmt, ap);
		va_end(ap);
		if (rc < 0) {
			*msg = '\0';
		}
	}

	if (*msg) {
		sz = log->write("S %ld.%06ld SIG%s %s\n", (int64_t)delta.tv_sec, (int64_t)delta.tv_usec, signum_to_signame(signum), msg);
	} else {
		sz = log->write("S %ld.%06ld SIG%s\n", (int64_t)delta.tv_sec, (int64_t)delta.tv_usec, signum_to_signame(signum));
	}

	log->oldtime = now;
	return sz;
}

// logInfo writes a message to the infolog
ssize_t ScriptControl::logInfo(const char *name, const char *msgfmt, ...) {
	char msg[BUFSIZ] = {0};
	va_list ap;
	ssize_t sz;

	ScriptLog* log = infolog;
	if (!log) {
		return 0;
	}

	assert(log->format == ScriptFormat::TimingMulti);
	DBG("  writing info to multi-stream log");

	if (msgfmt) {
		int rc;
		va_start(ap, msgfmt);
		rc = vsnprintf(msg, sizeof(msg), msgfmt, ap);
		va_end(ap);
		if (rc < 0) {
			*msg = '\0';;
		}
	}

	if (*msg) {
		sz = log->write("H %f %s %s\n", 0.0, name, msg);
	} else {
		sz = log->write("H %f %s\n", 0.0, name);
	}

	return sz;
}


void ScriptControl::loggingDone(const char *msg) {
	int status;

	DBG("stop logging");

	if (WIFSIGNALED(childstatus)) {
		status = WTERMSIG(childstatus) + 0x80;
	} else {
		status = WEXITSTATUS(childstatus);
	}

	DBG(" status=" << status);

	// close all output logs
	for (auto log : out.logs) {
		closeLog(log, msg, status);
		deleteLog(log);
	}
	out.logs.clear();

	// close all input logs
	for (auto log : in.logs) {
		closeLog(log, msg, status);
		deleteLog(log);
	}
	in.logs.clear();
}

// pty callback methods
void ScriptControl::ptyChildDie(pid_t child, int status) {
	child = static_cast<pid_t>(-1);
	childstatus = status;
}

void ScriptControl::ptyChildSigstop(pid_t child) {
	DBG(" child stop by SIGSTOP -- stop parent too");
	kill(getpid(), SIGSTOP);
	DBG(" resume");
	kill(child, SIGCONT);
}

int ScriptControl::ptyLogStreamActivity(int fd, char* buf, size_t bufsz) {
	ssize_t ssz = 0;

	DBG("stream activity callback");

	if (fd == STDIN_FILENO) {
		// from stdin (user) to command
		ssz = logStreamActivity(in, buf, (size_t) bufsz);
	} else if (fd == ul_pty_get_childfd(pty)) {
		// from command (master) to stdout and log
		ssz = logStreamActivity(out, buf, (size_t) bufsz);
	}

	if (ssz < 0) {
		return (int) ssz;
	}

	DBG(" append " << ssz << " bytes [summary=" << outsz << ", max=" << maxsz << "]");

	outsz += ssz;

	// check output limit
	if (maxsz != 0 && outsz >= maxsz) {
		if (!quiet)
			printf("Script terminated, max output files size %lu exceeded.\n", maxsz);
		DBG("output size " << outsz << ", exceeded limit " << maxsz);
		loggingDone("max output size exceeded");
		return 1;
	}
	return 0;
}

int ScriptControl::ptyLogSignal(struct signalfd_siginfo* info, void* sigdata) {
	ssize_t ssz = 0;

	switch (info->ssi_signo) {
	case SIGWINCH:
	{
		struct winsize* win = static_cast<winsize*>(sigdata);
		ssz = logSignal(info->ssi_signo, "ROWS=%d COLS=%d", win->ws_row, win->ws_col);
		break;
	}
	case SIGTERM:
		// FALLTHROUGH
	case SIGINT:
		// FALLTHROUGH
	case SIGQUIT:
		ssz = logSignal(info->ssi_signo, NULL);
		break;
	default:
		// no log
		break;
	}

	return ssz < 0 ? ssz : 0;
}

int ScriptControl::ptyFlushLogs() {
	for (auto log : out.logs) {
		int rc = log ? log->flush() : 0;
		if (rc) {
			return rc;
		}
	}

	for (auto log : in.logs) {
		int rc = log ? log->flush() : 0;
		if (rc) {
			return rc;
		}
	}
	return 0;
}
