#ifndef WIN32_PORT_H
#define WIN32_PORT_H

#include <windows.h>

#define O_CLOEXEC 0
#define AI_ADDRCONFIG  0x0400
#define AI_NUMERICSERV 0 //FIXME

#define PRId32 "I32d"
#define PRIu32 "I32u"
#define PRIu16 "hu"
#define PRIu64 "I64u"

int getpagesize (void);

#endif // WIN32_PORT_H
