#include "util.h"

#ifdef DO_COUNT
volatile sig_atomic_t count = 0;
# ifdef STATS_PIPE
volatile sig_atomic_t avg = 0;
volatile sig_atomic_t act = 0;
volatile sig_atomic_t rmx = 0;
# endif
volatile sig_atomic_t gif = 0;
volatile sig_atomic_t err = 0;
# ifdef TEXT_REPLY
volatile sig_atomic_t txt = 0;
volatile sig_atomic_t bad = 0;
#  ifdef NULLSERV_REPLIES
volatile sig_atomic_t jpg = 0;
volatile sig_atomic_t png = 0;
volatile sig_atomic_t swf = 0;
volatile sig_atomic_t ico = 0;
#  endif
# ifdef SSL_RESP
volatile sig_atomic_t ssl = 0;
# endif
# endif  // TEXT_REPLY
# ifdef STATS_REPLY
volatile sig_atomic_t sta = 0;
volatile sig_atomic_t stt = 0;
# endif // STATS_REPLY
# ifdef REDIRECT
volatile sig_atomic_t rdr = 0;
# endif // REDIRECT
volatile sig_atomic_t tmo = 0;
volatile sig_atomic_t cls = 0;
volatile sig_atomic_t nou = 0;
volatile sig_atomic_t pth = 0;
volatile sig_atomic_t nfe = 0;
volatile sig_atomic_t ufe = 0;
#endif  // DO_COUNT

char* get_version(char* program_name)
{
  char* retbuf = NULL;

//  asprintf(&retbuf, "%s version: %s compiled: %s from %s", program_name, VERSION, __DATE__ " " __TIME__, __FILE__);
  asprintf(&retbuf, "%s version: %s compiled: %s", program_name, VERSION, __DATE__ " " __TIME__);

  return retbuf;
}

#ifdef DO_COUNT
char* get_stats(int sta_offset, int stt_offset)
{
  char* retbuf = NULL;

  asprintf(&retbuf, "%d req"
# ifdef STATS_PIPE
    ", %d avg, %d rmx"
# endif
    ", %d err, %d tmo, %d cls, %d nou, %d pth, %d nfe, %d ufe, %d gif"
# ifdef TEXT_REPLY
    ", %d bad, %d txt"
#  ifdef NULLSERV_REPLIES
    ", %d jpg, %d png, %d swf, %d ico"
#  endif
#  ifdef SSL_RESP
    ", %d ssl"
#  endif
# endif  // TEXT_REPLY
# ifdef STATS_REPLY
    ", %d sta, %d stt"
# endif // STATS_REPLY
# ifdef REDIRECT
    ", %d rdr"
# endif // REDIRECT
    , count
# ifdef STATS_PIPE
    , avg, rmx
# endif
    , err, tmo, cls, nou, pth, nfe, ufe, gif
# ifdef TEXT_REPLY
    , bad, txt
#  ifdef NULLSERV_REPLIES
    , jpg, png, swf, ico
#  endif
#  ifdef SSL_RESP
    , ssl
#  endif
# endif  // TEXT_REPLY
# ifdef STATS_REPLY
    , sta + sta_offset, stt + stt_offset
# endif // STATS_REPLY
# ifdef REDIRECT
    , rdr
# endif // REDIRECT
  );

  return retbuf;
}
#endif // DO_COUNT
