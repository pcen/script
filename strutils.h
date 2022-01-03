#ifndef STRUTIL_H
#define STRUTIL_H

#include <string.h>

const char* startswith(const char *s, const char *prefix) {
	size_t sz = prefix ? strlen(prefix) : 0;

	if (s && sz && strncmp(s, prefix, sz) == 0) {
		return s + sz;
	}
	return nullptr;
}

const char* startswith_no_case(const char *s, const char *prefix) {
	size_t sz = prefix ? strlen(prefix) : 0;

	if (s && sz && strncasecmp(s, prefix, sz) == 0) {
		return s + sz;
	}
	return nullptr;
}

const char* endswith(const char *s, const char *postfix) {
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

#endif // STRUTIL_H
