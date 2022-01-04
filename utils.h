#ifndef UTILS_H
#define UTILS_H

#include <string.h>
#include <time.h>

#include <chrono>

#define ARRAY_SIZE(arr) ((sizeof(arr) / sizeof(*(arr))) / static_cast<size_t>(!(sizeof(arr) % sizeof(*(arr)))))

#ifdef O_CLOEXEC
#define UL_CLOEXECSTR "e"
#else
#define UL_CLOEXECSTR ""
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef IUTF8
#define IUTF8 0040000
#endif

inline int xusleep(useconds_t usec) {
	struct timespec waittime = {
		.tv_sec   =  usec / 1000000L,
		.tv_nsec  = (usec % 1000000L) * 1000
	};
	return nanosleep(&waittime, NULL);
}

inline const char* startswith(const char *s, const char *prefix) {
	size_t sz = prefix ? strlen(prefix) : 0;

	if (s && sz && strncmp(s, prefix, sz) == 0) {
		return s + sz;
	}
	return nullptr;
}

inline const char* startswith_no_case(const char *s, const char *prefix) {
	size_t sz = prefix ? strlen(prefix) : 0;

	if (s && sz && strncasecmp(s, prefix, sz) == 0) {
		return s + sz;
	}
	return nullptr;
}

inline const char* endswith(const char *s, const char *postfix) {
	size_t sl = s ? strlen(s) : 0;
	size_t pl = postfix ? strlen(postfix) : 0;

	if (pl == 0)
		return s + sl;
	if (sl < pl)
		return nullptr;
	if (memcmp(s + sl - pl, postfix, pl) != 0)
		return nullptr;
	return s + sl - pl;
}

inline void gettime_monotonic(struct timeval *tv) {
	auto tp = std::chrono::steady_clock::now();
	auto s = std::chrono::time_point_cast<std::chrono::seconds>(tp);
	if (s > tp) s -= std::chrono::seconds(1);
	auto us = std::chrono::duration_cast<std::chrono::microseconds>(tp - s);
	tv->tv_sec = s.time_since_epoch().count();
	tv->tv_usec = us.count();
}

#endif // UTILS_H
