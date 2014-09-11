#ifndef UTIL_H
#define UTIL_H

// common configuration items

// preprocessor defines
#define VERSION "V35.HZ10"

#define BACKLOG 30              // how many pending connections queue will hold
#define CHAR_BUF_SIZE 4095      // surprising how big requests can be with cookies and lengthy yahoo url!

#define DEFAULT_IP "*"          // default IP address ALL - use this in messages only
#define DEFAULT_PORT "80"       // the default port users will be connecting to
#define DEFAULT_TIMEOUT 10      // default timeout for select() calls, in seconds

#ifdef MULTIPORT
# ifndef PORT_MODE
#  define PORT_MODE
# endif
# define SECOND_PORT "443"
# define MAX_PORTS 10
#else
# define MAX_PORTS 1
#endif

#ifdef DROP_ROOT
# define DEFAULT_USER "nobody"  // nobody used by dnsmasq
#endif

#ifdef REDIRECT
# define TEXT_REPLY
#endif

#ifdef STATS_PIPE
# ifndef DO_COUNT
#  define DO_COUNT
# endif
#endif

#ifdef STATS_REPLY
# ifndef DO_COUNT
#  define DO_COUNT
# endif
# define DEFAULT_STATS_URL "/servstats"
# define DEFAULT_STATS_TEXT_URL "/servstats.txt"
#endif

# define _GNU_SOURCE            // asprintf()

#ifdef TEST
# define TEXT_REPLY 1
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

#ifdef TINY
/* redefine log functions to NULL */
# define openlog(x,y...)
# define syslog(x,y...)
#endif

#define OK (0)
#define ERROR (-1)

// system includes
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>        // for TCP_NODELAY
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
//#include <net/if.h>             // for IFNAMSIZ (OBE - commented out)
#include <pwd.h>                // for getpwnam
#include <ctype.h>              // isdigit() & tolower()

// shared enums
enum responsetypes {
  SEND_GIF = 10,
  SEND_TXT,
  SEND_JPG,
  SEND_PNG,
  SEND_SWF,
  SEND_ICO,
  SEND_BAD,
#ifdef SSL_RESP
  SEND_SSL,
#endif
#ifdef STATS_REPLY
  SEND_STATS,
  SEND_STATSTEXT,
#endif
#ifdef REDIRECT
  SEND_REDIRECT,
#endif
  SEND_NO_EXT,
  SEND_UNK_EXT,
  SEND_NO_URL,
  SEND_BAD_PATH,
  FAIL_TIMEOUT,
  FAIL_CLOSED
};

// cross-thread count variables
#ifdef DO_COUNT
extern volatile sig_atomic_t count;
# ifdef STATS_PIPE
extern volatile sig_atomic_t avg; // cumulative moving average request size
extern volatile sig_atomic_t act; // count (updated at time of average calculation)
extern volatile sig_atomic_t rmx; // maximum encountered request size
# endif
extern volatile sig_atomic_t gif;
extern volatile sig_atomic_t err;
# ifdef TEXT_REPLY
extern volatile sig_atomic_t txt;
extern volatile sig_atomic_t bad;
#  ifdef NULLSERV_REPLIES
extern volatile sig_atomic_t jpg;
extern volatile sig_atomic_t png;
extern volatile sig_atomic_t swf;
extern volatile sig_atomic_t ico;
#  endif
# ifdef SSL_RESP
extern volatile sig_atomic_t ssl;
# endif
# endif  // TEXT_REPLY
# ifdef STATS_REPLY
extern volatile sig_atomic_t sta; // so meta!
extern volatile sig_atomic_t stt;
# endif // STATS_REPLY
# ifdef REDIRECT
extern volatile sig_atomic_t rdr;
# endif // REDIRECT
extern volatile sig_atomic_t tmo;
extern volatile sig_atomic_t cls;
extern volatile sig_atomic_t nou;
extern volatile sig_atomic_t pth;
extern volatile sig_atomic_t nfe;
extern volatile sig_atomic_t ufe;
#endif  // DO_COUNT

// util.c functions

// generate version string
// note that caller is expected to call free()
//  on the return value when done using it
char* get_version(char* program_name);

#ifdef DO_COUNT
// stats string generator
// NOTES:
// - The return value is heap-allocated, so the caller is expected to call
//   free() on the return value when done using it in order to avoid a memory
//   leak.
// - The purpose of sta_offset is to allow accounting for an in-progess status
//   response.
// - Similarly, stt_offset is for an in-progress status.txt response.
char* get_stats(int sta_offset, int stt_offset);
#endif

// changelog
/*
V1  Proof of concept mstombs www.linkysinfo.org 06/09/09
V2  usleep after send to delay socket close 08/09/09
V3  TCP_NODELAY not usleep 09/09/09
V4  daemonize with syslog 10/09/09
V5  usleep back in 10/09/09
V6  only use IPV4, add linger and shutdown to avoid need for sleep 11/09/09
  Consistent exit codes and version stamp
V7  use shutdown/read/shutdown to cleanly flush and close connection
V8  add inetd and listening IP option
V9  minimalize
V10  make inetd mode compiler option -DINETD_MODE
V11  debug TCP_NODELAY back and MSG_DONTWAIT flag on send
V12  Change read to recv with MSG_DONTWAIT and add MSG_NOSIGNAL on send
V13  DONTWAIT's just trigger RST connection closing so remove
V14  Back to V8 fork(), add header "connection: close"" and reformat pixel def
V15  add command line options for variable port 2nd March 2010
V16  add command line option for ifname, add SO_LINGER2 to not hang in FIN_WAIT2
V17  only send null pixel if image requested, make most options compiler options to make small version
V18  move image file test back into TEST
V19  add TINY build which has no output.
V20  Remove default interface "br0" assignment"
  amend http header to not encourage server like byte requests"
  use CHAR_BUF_SIZE rather than sizeof
  try again to turn off FIN_WAIT2
V21  run as user nobody by default
V22  Use apache style close using select to timeout connection
  and not leave dormant processes lying around if browser doeesn't close connection cleanly
  use SIGURS1 for report count, not system signal SIGHUP - thanks Rodney
V23  be more selective about replies
V24  common signal_handler and minor mods to minimize size
  Fix V23 bugs and use null string and javascript detection by ~nephelim~
V25  test version for robust parsing of path
V26  timeout on recv, block signals in child, enhance stats collection, fix bug in "-u user"
V27  add error reply messages
V28  move log, add option to read nullpixel from file.
V29  add option to read gif from file
V30  tidy up
V31 development - add nullserv responses from https://github.com/flexiondotorg/nullserv 30/05/13
V32 Add candidate SSL response
V33 reduce size of gif and png - NOT the same as https://github.com/h0tw1r3/pixelserv which has extra DECODE_URL option
V34 add MULTIPORT option to also listen by default on https port 443
 |
V34.1 minor changes like bigger buffer, added ip/port info in abort msgs etc by opav @ https://github.com/opav/pixelserv-openwrt
V35 Make user change failures non fatal, smaller swf file, investigate jpg structure, revert to more compatible 169 byte version
V35.HZ1  merge in a bunch of h0tw1r3 changes (mainly REDIRECT feature) in attempt to bring the forks back together
V35.HZ2  fix botched merge of redirect code, prevent memory leak, optimize self-redirect check loop
V35.HZ3  add .ico response, mainly to support favicon requests
V35.HZ4  add stats response URL feature, fix stats typo
V35.HZ5  fixed stats response HTML output, log send() errors to syslog
V35.HZ6  fix length of stats response
V35.HZ7  add plaintext stats response
         add syslog logging of various EXIT_FAILURE conditions
         add counters for "connection timeout" and "connection closed" failure cases
         add counters for "no extension", "unsupported extension", "no URL", and "bad path" default response cases
         add configurable timeout(s)
         increase default timeout(s) per mstombs suggestion
         integrate transparent+caching .ico response from M0g13r/mstombs
V35.HZ8  suppress syslog regarding unexpectedly closed socket connection
V35.HZ9  use pipe to report client request sizes, and report average and max request size stats
V35.HZ10 split code into multiple files for organizational and encapsulation purposes
*/

#endif // UTIL_H
