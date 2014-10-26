#ifndef UTIL_H
#define UTIL_H

// common configuration items

#define _GNU_SOURCE             // using a bunch of gcc-specific stuff

// system includes used by more than one source file
#include <errno.h>              // EPIPE, errno, EINTR
#include <netdb.h>              // addrinfo(), AI_PASSIVE, gai_strerror(), freeaddrinfo()
//#include <net/if.h>           // IFNAMSIZ
//#include <netinet/in.h>       // doesn't seem to be needed
#include <netinet/tcp.h>        // SOL_TCP, TCP_NODELAY
#include <signal.h>             // sig_atomic_t
#include <stdio.h>              // printf() and variants
#include <stdlib.h>             // exit(), EXIT_FAILURE
#include <string.h>             // lots of stuff!
#include <syslog.h>             // syslog(), openlog()
//#include <sys/socket.h>       // doesn't seem to be needed
//#include <sys/types.h>        // doesn't seem to be needed
#include <unistd.h>             // close(), setuid(), TEMP_FAILURE_RETRY, fork()

// preprocessor defines
#define VERSION "V35.HZ11WIP4"

#define BACKLOG SOMAXCONN       // how many pending connections queue will hold
#define CHAR_BUF_SIZE 4095      // surprising how big requests can be with cookies and lengthy yahoo url!

#define DEFAULT_IP "*"          // default IP address ALL - use this in messages only
#define DEFAULT_PORT "80"       // the default port users will be connecting to
#define DEFAULT_TIMEOUT 10      // default timeout for select() calls, in seconds


#define SECOND_PORT "443"
#define MAX_PORTS 10

#ifdef DROP_ROOT
# define DEFAULT_USER "nobody"  // nobody used by dnsmasq
#endif

# define DEFAULT_STATS_URL "/servstats"
# define DEFAULT_STATS_TEXT_URL "/servstats.txt"

#ifdef TEST
# define VERBOSE 1
# define TESTPRINT printf
#else
# define TESTPRINT(x,y...)
#endif

#ifdef VERBOSE
# define MYLOG syslog
#else  // rely on optimiser to remove redundant code
# define MYLOG(x,y...)
#endif

// cross-thread count variables
extern volatile sig_atomic_t count;
extern volatile sig_atomic_t avg; // cumulative moving average request size
extern volatile sig_atomic_t act; // count (updated at time of average calculation)
extern volatile sig_atomic_t rmx; // maximum encountered request size
extern volatile sig_atomic_t gif;
extern volatile sig_atomic_t err;
extern volatile sig_atomic_t txt;
extern volatile sig_atomic_t bad;
extern volatile sig_atomic_t jpg;
extern volatile sig_atomic_t png;
extern volatile sig_atomic_t swf;
extern volatile sig_atomic_t ico;
extern volatile sig_atomic_t ssl;
extern volatile sig_atomic_t sta; // so meta!
extern volatile sig_atomic_t stt;
extern volatile sig_atomic_t noc;
extern volatile sig_atomic_t rdr;
extern volatile sig_atomic_t tmo;
extern volatile sig_atomic_t cls;
extern volatile sig_atomic_t nou;
extern volatile sig_atomic_t pth;
extern volatile sig_atomic_t nfe;
extern volatile sig_atomic_t ufe;

// util.c functions

// generate version string
// note that caller is expected to call free()
//  on the return value when done using it
char* get_version(const char* const program_name);

// stats string generator
// NOTES:
// - The return value is heap-allocated, so the caller is expected to call
//   free() on the return value when done using it in order to avoid a memory
//   leak.
// - The purpose of sta_offset is to allow accounting for an in-progess status
//   response.
// - Similarly, stt_offset is for an in-progress status.txt response.
char* get_stats(const int sta_offset, const int stt_offset);

#endif // UTIL_H
