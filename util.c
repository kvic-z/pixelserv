#include "util.h"

// make gcc happy
#ifdef DEBUG
void dummy() {
  SET_LINE_NUMBER(__LINE__)
}
#endif

// stats data
// note that child processes inherit a snapshot copy
// public data (should probably change to a struct)
volatile sig_atomic_t count = 0;
volatile sig_atomic_t avg = 0;
volatile sig_atomic_t act = 0;
volatile sig_atomic_t rmx = 0;
volatile sig_atomic_t tct = 0;
volatile sig_atomic_t tav = 0;
volatile sig_atomic_t tmx = 0;
volatile sig_atomic_t err = 0;
volatile sig_atomic_t tmo = 0;
volatile sig_atomic_t cls = 0;
volatile sig_atomic_t nou = 0;
volatile sig_atomic_t pth = 0;
volatile sig_atomic_t nfe = 0;
volatile sig_atomic_t ufe = 0;
volatile sig_atomic_t gif = 0;
volatile sig_atomic_t bad = 0;
volatile sig_atomic_t txt = 0;
volatile sig_atomic_t jpg = 0;
volatile sig_atomic_t png = 0;
volatile sig_atomic_t swf = 0;
volatile sig_atomic_t ico = 0;
volatile sig_atomic_t ssl = 0;
volatile sig_atomic_t sta = 0;
volatile sig_atomic_t stt = 0;
volatile sig_atomic_t noc = 0;
volatile sig_atomic_t rdr = 0;
volatile sig_atomic_t pst = 0;
volatile sig_atomic_t hed = 0;

// private data
static struct timespec startup_time = {0, 0};

char* get_version(int argc, char* argv[]) {
  char* retbuf = NULL;
  char* optbuf = NULL;
  unsigned int optlen = 0, i = 1;
  unsigned int arglen[argc];

  // capture startup_time if not yet set
  if (!startup_time.tv_sec) {
    if (clock_gettime(CLOCK_MONOTONIC, &startup_time) < 0) {
      syslog(LOG_ERR, "clock_gettime() reported failure getting startup time: %m");
      return NULL;
    }
  }

  // determine total size of all arguments
  for (i = 1; i < argc; ++i)
  {
    arglen[i] = strlen(argv[i]) + 1; // add 1 for leading space
    optlen += arglen[i];
  }
  if (optlen > 0) {
    // allocate a buffer to hold all arguments
    optbuf = malloc((optlen * sizeof(char)) + 1);
  }
  if (optbuf) {
    for (i = 1, optlen = 0; i < argc; ++i) {
      optbuf[optlen] = ' '; // prepend a space to each argument
      strncpy(optbuf + optlen + 1, argv[i], arglen[i]);
      optlen += arglen[i];
    }
    optbuf[optlen] = '\0';
    asprintf(&retbuf, "%s version: %s compiled: %s options:%s", argv[0], VERSION, __DATE__ " " __TIME__, optbuf);
    free(optbuf);
  } else {
    asprintf(&retbuf, "%s version: %s compiled: %s options: <malloc() error>", argv[0], VERSION, __DATE__ " " __TIME__);
  }

  return retbuf;
}

char* get_stats(const int sta_offset, const int stt_offset) {
  char* retbuf = NULL;
  struct timespec current_time;
  double uptime;

  if (clock_gettime(CLOCK_MONOTONIC, &current_time) < 0) {
    syslog(LOG_WARNING, "clock_gettime() reported failure getting current time: %m");
    current_time = startup_time;
  }
  uptime = difftime(current_time.tv_sec, startup_time.tv_sec);

  asprintf(&retbuf
         , "%.0f uts, %d req, %d avg, %d rmx, %d tav, %d tmx, %d err, %d tmo, %d cls, %d nou, %d pth, %d nfe, %d ufe, %d gif, %d bad, %d txt, %d jpg, %d png, %d swf, %d ico, %d ssl, %d sta, %d stt, %d 204, %d rdr, %d pst, %d hed"
         , uptime, count, avg, rmx, tav, tmx, err, tmo, cls, nou, pth, nfe, ufe, gif, bad, txt, jpg, png, swf, ico, ssl, sta + sta_offset, stt + stt_offset, noc, rdr, pst, hed
  );

  return retbuf;
}
