#ifndef UTILS_H
#define UTILS_H

#include <ctime>
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
	timespec waittime{usec / 1000000L, (usec % 1000000L) * 1000};
	return nanosleep(&waittime, nullptr);
}

inline timeval getMonotonicTime() {
	auto tp = std::chrono::steady_clock::now();
	auto s = std::chrono::time_point_cast<std::chrono::seconds>(tp);
	if (s > tp) s -= std::chrono::seconds(1);
	auto us = std::chrono::duration_cast<std::chrono::microseconds>(tp - s);
	return timeval{ s.time_since_epoch().count(), us.count() };
}

#endif // UTILS_H
