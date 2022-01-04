#ifndef UTILS_H
#define UTILS_H

#include <string.h>
#include <time.h>

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

#endif // UTILS_H
