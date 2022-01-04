#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
#include <iostream>
#define DBG(x) do { \
	std::cerr << __FILE__ << ": " << x << std::endl; \
} while (false)
#else // !DEBUG
#define DBG(x)
#endif

#endif // DEBUG_H
