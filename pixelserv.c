/*
* pixelserv.c a small mod to public domain server.c -- a stream socket server demo
* from http://beej.us/guide/bgnet/
* single pixel http string from http://proxytunnel.sourceforge.net/pixelserv.php
*/

#define VERSION "V35.HZ1"

#define BACKLOG 30              // how many pending connections queue will hold
#define CHAR_BUF_SIZE 2048	     // surprising how big requests can be with cookies and lengthy yahoo url!

#define DEFAULT_IP "*"          // default IP address ALL - use this in messages only
#define DEFAULT_PORT "80"       // the default port users will be connecting to

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

# define _GNU_SOURCE            // asprintf()

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

#ifdef HEX_DUMP
/* from http://sws.dett.de/mini/hexdump-c/ */
static void hex_dump(void *data, int size)
{
  /* dumps size bytes of *data to stdout. Looks like:
   * [0000] 75 6E 6B 6E 6F 77 6E 20   30 FF 00 00 00 00 39 00 unknown 0.....9.
   * (in a single line of course)
   */

  unsigned char *p = data;
  unsigned char c;
  int n;
  char bytestr[4] = {0};
  char addrstr[10] = {0};
  char hexstr[16*3 + 5] = {0};
  char charstr[16*1 + 5] = {0};
  for (n = 1; n <= size; n++) {
    if (n%16 == 1) {
      /* store address for this line */
      snprintf(addrstr, sizeof addrstr, "%.4x",
         ((unsigned int)p-(unsigned int)data) );
    }

    c = *p;
    if (isprint(c) == 0) {
      c = '.';
    }

    /* store hex str (for left side) */
    snprintf(bytestr, sizeof bytestr, "%02X ", *p);
    strncat(hexstr, bytestr, sizeof hexstr - strlen(hexstr) - 1);

    /* store char str (for right side) */
    snprintf(bytestr, sizeof bytestr, "%c", c);
    strncat(charstr, bytestr, sizeof charstr - strlen(charstr) - 1);

    if (n%16 == 0) {
      /* line completed */
      printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
      hexstr[0] = 0;
      charstr[0] = 0;
    } else if (n%8 == 0) {
      /* half line: add whitespaces */
      strncat(hexstr, "  ", sizeof hexstr - strlen(hexstr) - 1);
      strncat(charstr, " ", sizeof charstr - strlen(charstr) - 1);
    }

    p++; /* next byte */
  }

  if (strlen(hexstr) > 0) {
    /* print rest of buffer if not empty */
    printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
  }
}
#endif

#ifdef REDIRECT
char * strstr_last(const char *str1, const char *str2) {
  char *strp;
  int len1, len2;
  len2 = strlen(str2);
  if (len2==0) {
    return (char *) str1;
  }
  len1 = strlen(str1);
  if (len1 - len2 <= 0) {
    return 0;
  }
  strp = (char *)(str1 + len1 - len2);
  while (strp != str1) {
    if (*strp == *str2 && strncmp(strp, str2, len2) == 0) {
      return strp;
    }
    strp--;
  }
  return 0;
}

char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

void urldecode(char *decoded, char *encoded) {
    char *pstr = encoded, *pbuf = decoded;

    while (*pstr) {
      if (*pstr == '%') {
        if (pstr[1] && pstr[2]) {
            *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
            pstr += 2;
        }
      } else {
        *pbuf++ = *pstr;
      }
      pstr++;
    }
    *pbuf = '\0';
}
#endif // REDIRECT

#ifdef READ_FILE
# include <sys/stat.h>
#endif

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

enum responsetypes {
  SEND_GIF = 10,
  SEND_TXT,
  SEND_JPG,
  SEND_PNG,
  SEND_SWF,
  SEND_BAD,
#ifdef REDIRECT
  SEND_SSL,
  SEND_REDIRECT
#else
  SEND_SSL
#endif
};

#ifdef DO_COUNT
volatile sig_atomic_t count = 0;
volatile sig_atomic_t gif = 0;
volatile sig_atomic_t err = 0;
# ifdef TEXT_REPLY
volatile sig_atomic_t txt = 0;
volatile sig_atomic_t bad = 0;
#  ifdef NULLSERV_REPLIES
volatile sig_atomic_t jpg = 0;
volatile sig_atomic_t png = 0;
volatile sig_atomic_t swf = 0;
#  endif
# ifdef SSL_RESP
volatile sig_atomic_t ssl = 0;
# endif
# endif  // TEXT_REPLY
# ifdef REDIRECT
volatile sig_atomic_t rdr = 0;
# endif // REDIRECT
#endif  // DO_COUNT

void signal_handler(int sig)  // common signal handler
{
  int status;
  switch (sig) {
  case SIGCHLD :  // ensure no zombie sub processes left */
    while ( waitpid(-1, &status, WNOHANG) > 0 ) {
#ifdef DO_COUNT
      if ( WIFEXITED(status) ) {
        switch ( WEXITSTATUS(status) ) {
          case EXIT_FAILURE :
            err++;
            break;

          case SEND_GIF :
            gif++;
            break;
# ifdef REDIRECT
          case SEND_REDIRECT:
            rdr++;
            break;
# endif // REDIRECT
# ifdef TEXT_REPLY
          case SEND_BAD :
            bad++;
            break;

          case SEND_TXT :
            txt++;
            break;
#  ifdef NULLSERV_REPLIES
          case SEND_JPG :
            jpg++;
            break;

          case SEND_PNG :
            png++;
            break;

          case SEND_SWF :
            swf++;
            break;
#  endif  // NULLSERV_REPLIES
#  ifdef SSL_RESP
          case SEND_SSL :
            ssl++;
            break;
#  endif
# endif  // TEXT_REPLY
        }
      }
#endif  // DO_COUNT
    };
    return;

#ifndef TINY
  case SIGTERM :  // Handler for the SIGTERM signal (kill)
    signal(sig, SIG_IGN);  // Ignore this signal while we are quiting
# ifdef DO_COUNT
  case SIGUSR1 :
    syslog(LOG_INFO, "%d req, %d err, %d gif,"
#  ifdef TEXT_REPLY
      " %d bad, %d txt"
#   ifdef NULLSERV_REPLIES
      ", %d jpg, %d png, %d swf"
#   endif
#   ifdef SSL_RESP
      ", %d ssl"
#   endif
#  endif  // TEXT_REPLY
#  ifdef REDIRECT
           ", %d rdr"
#  endif // REDIRECT
      , count, err, gif
#  ifdef TEXT_REPLY
      , bad, txt
#   ifdef NULLSERV_REPLIES
      , jpg, png, swf
#   endif
#   ifdef SSL_RESP
      , ssl
#   endif
#  endif  // TEXT_REPLY
#  ifdef REDIRECT
           , rdr
#  endif // REDIRECT
      );

    if (sig == SIGUSR1) {
      return;
    }

# endif  // DO_COUNT
    syslog(LOG_NOTICE, "exit on SIGTERM");
    exit(EXIT_SUCCESS);
#endif // TINY
  }
}

#ifdef TEST
void *get_in_addr(struct sockaddr *sa) // get sockaddr, IPv4 or IPv6
{
  if (sa->sa_family == AF_INET) {
    return &(( (struct sockaddr_in*) sa )->sin_addr);
  }

  return &(( (struct sockaddr_in6*) sa )->sin6_addr);
}
#endif

int main (int argc, char *argv[]) // program start
{
  int sockfd;  // listen on sock_fd
  int new_fd;  // new connection on new_fd
  struct sockaddr_storage their_addr;  // connector's address information
  socklen_t sin_size;
  int yes = 1;
#ifdef TEST
  char s[INET6_ADDRSTRLEN];
#endif
  int rv;
  char *ip_addr = DEFAULT_IP;
  int use_ip = 0;
  char buf[CHAR_BUF_SIZE + 1];

#ifdef PORT_MODE
  char *ports[MAX_PORTS];
  ports[0] = DEFAULT_PORT;
  char *port;
#ifdef MULTIPORT
  fd_set readfds;
  int sockfds[MAX_PORTS];
  ports[1] = SECOND_PORT;
#endif
  int num_ports = 0;
#else
# define port DEFAULT_PORT
#endif
  int i;

#ifdef IF_MODE
  char *ifname = "";
  int use_if = 0;
#endif

#ifdef DROP_ROOT
  char *user = DEFAULT_USER;  // used to be long enough
  struct passwd *pw;
#endif

#ifdef REDIRECT
  int do_redirect = 0;

# ifdef TEXT_REPLY
  char *location = NULL;
  char *url = NULL;
  char *bufptr = NULL;
# endif // TEXT_REPLY
#endif // REDIRECT

#ifdef READ_FILE
  char *fname = NULL;
  int fsize;
# ifdef READ_GIF
  int do_gif = 0;
# endif
  int hsize = 0;
  struct stat file_stat;
  FILE *fp;
#endif // READ_FILE

#ifdef REDIRECT
# ifdef TEXT_REPLY
  static const char *httpredirect =
  "HTTP/1.1 307 Temporary Redirect\r\n"
  "Location: %s\r\n"
  "Content-type: text/plain\r\n"
  "Content-length: 0\r\n"
  "Connection: close\r\n\r\n";
# endif // TEXT_REPLY
#endif // REDIRECT

  static unsigned char httpnullpixel[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/gif\r\n"
  "Content-length: 42\r\n"
  "Connection: close\r\n"
  "\r\n"
  "GIF89a" // header
  "\1\0\1\0"  // little endian width, height
  "\x80"    // Global Colour Table flag
  "\0"    // background colour
  "\0"    // default pixel aspect ratio
  "\1\1\1"  // RGB
  "\0\0\0"  // RBG black
  "!\xf9"  // Graphical Control Extension
  "\4"  // 4 byte GCD data follow
  "\1"  // there is transparent background color
  "\0\0"  // delay for animation
  "\0"  // transparent colour
  "\0"  // end of GCE block
  ","  // image descriptor
  "\0\0\0\0"  // NW corner
  "\1\0\1\0"  // height * width
  "\0"  // no local color table
  "\2"  // start of image LZW size
  "\1"  // 1 byte of LZW encoded image data
  "D"    // image data
  "\0"  // end of image data
  ";";  // GIF file terminator

#ifdef TEXT_REPLY
  static unsigned char httpnulltext[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html\r\n"
  "Content-length: 0\r\n"
  "Connection: close\r\n"
  "\r\n";

  static unsigned char http501[] =
  "HTTP/1.1 501 Method Not Implemented\r\n"
  "Connection: close\r\n"
  "\r\n";

#ifdef NULLSERV_REPLIES
  static unsigned char httpnull_png[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/png\r\n"
  "Content-length: 67\r\n"
  "Connection: close\r\n"
  "\r\n"
  "\x89"
  "PNG"
  "\r\n"
  "\x1a\n"  // EOF
  "\0\0\0\x0d" // 13 bytes length
  "IHDR"
  "\0\0\0\1\0\0\0\1"  // width x height
  "\x08"  // bit depth
  "\x06"  // Truecolour with alpha
  "\0\0\0"  // compression, filter, interlace
  "\x1f\x15\xc4\x89"  // CRC
  "\0\0\0\x0a"  // 10 bytes length
  "IDAT"
  "\x78\x9c\x63\0\1\0\0\5\0\1"
  "\x0d\x0a\x2d\xb4"  // CRC
  "\0\0\0\0"  // 0 length
  "IEND"
  "\xae\x42\x60\x82";  // CRC

  static unsigned char httpnull_jpg[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/jpeg\r\n"
	"Content-length: 159\r\n"
  "Connection: close\r\n"
  "\r\n"
  "\xff\xd8"   // SOI, Start Of Image
  "\xff\xe0"  // APP0
  "\x00\x10"  // length of section 16
  "JFIF\0"
  "\x01\x01"  // version 1.1
  "\x01"    // pixel per inch
  "\x00\x48"  // horizontal density 72
  "\x00\x48"  // vertical density 72
  "\x00\x00"  // size of thumbnail 0 x 0
  "\xff\xdb"  // DQT
  "\x00\x43"  // length of section 3+64
  "\x00"    // 0 QT 8 bit
	"\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xc0"	// SOF
	"\x00\x0b"	// length 11
	"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
	"\xff\xc4"	// DHT Define Huffman Table
	"\x00\x14"	// length 20
	"\x00\x01"	// DC table 1
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x03"
	"\xff\xc4"	// DHT
	"\x00\x14"	// length 20
	"\x10\x01"	// AC table 1
	"\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00"
  "\xff\xda"  // SOS, Start of Scan
  "\x00\x08"  // length 8
  "\x01"    // 1 component
  "\x01\x00"
  "\x00\x3f\x00"  // Ss 0, Se 63, AhAl 0
	"\x37" // image
  "\xff\xd9";  // EOI, End Of image

static unsigned char httpnull_swf[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: application/x-shockwave-flash\r\n"
  "Content-length: 25\r\n"
  "Connection: close\r\n"
  "\r\n"
  "FWS"
  "\x05"  // File version
  "\x19\x00\x00\x00"  // litle endian size 16+9=25
  "\x30\x0A\x00\xA0"  // Frame size 1 x 1
  "\x00\x01"  // frame rate 1 fps
  "\x01\x00"  // 1 frame
  "\x43\x02"  // tag type is 9 = SetBackgroundColor block 3 bytes long
  "\x00\x00\x00"  // black
  "\x40\x00"  // tag type 1 = show frame
  "\x00\x00";  // tag type 0 - end file
# endif

# ifdef SSL_RESP
static unsigned char SSL_no[] =
  "\x15"  // Alert 21
  "\3\0"  // Version 3.0
  "\0\2"  // length 2
  "\2"    // fatal
  "\x31"; // 0 close notify, 0x28 Handshake failure 40, 0x31 TLS access denied 49
# endif
#endif // TEXT_REPLY

#ifdef NULLSERV_REPLIES
# define DEFAULT_REPLY SEND_TXT
  unsigned char *response = httpnulltext;
  int rsize = sizeof httpnulltext - 1;
#else
# define DEFAULT_REPLY SEND_GIF
  unsigned char *response = httpnullpixel;
  int rsize = sizeof httpnullpixel - 1;
#endif

  struct addrinfo hints, *servinfo;
  int error = 0;

  fd_set set;
  struct timeval timeout;
  int select_rv;
  int status = EXIT_FAILURE; /* default return from child */

  /* command line arguments processing */
  for (i = 1; i < argc; i++)  {
    if (argv[i][0] == '-') {
      if ( (i + 1) < argc ) {
        switch (argv[i][1]) {
#ifdef IF_MODE
        case 'n' :
          ifname = argv[++i];
          use_if = 1;
          break;
#endif
#ifdef PORT_MODE
        case 'p' :
          if (num_ports < MAX_PORTS) {
            ports[num_ports++] = argv[++i];
          } else {
            i++;
            error = 1;
          }
          break;
#endif
#ifdef DROP_ROOT
        case 'u' :
          user = argv[++i];
          break;
#endif
#ifdef READ_FILE
# ifdef READ_GIF
        case 'g' :
          do_gif = 1;  // and fall through
# endif
        case 'f' :
          fname = argv[++i];
          break;
#endif  // READ_FILE
        default :
          error = 1;
        }
#ifdef REDIRECT
      } else if (argv[i][1] == 'r') {
          do_redirect = 1;
          break;
#endif
      } else {
        error = 1;
      }
    } else if (use_ip == 0) {  // assume its a listening IP address
      ip_addr = argv[i];
      use_ip = 1;
    } else {
      error = 1;  // fix bug with 2 IP like args
    }
  }

  if (error) {
#ifndef TINY
    printf("Usage:%s"
           " [IP No/hostname (all)]"
# ifdef PORT_MODE
           " [-p port (80)"
# ifdef MULTIPORT
           " & (443)"
# endif
           "]"
# endif
# ifdef IF_MODE
           " [-n i/f (all)]"
# endif // IF_MODE
# ifdef DROP_ROOT
           " [-u user (\"nobody\")]"
# endif // DROP_ROOT
#ifdef REDIRECT
           " [-r redirect encoded path (tracker links)]"
#endif // REDIRECT
# ifdef READ_FILE
           " [-f response.bin]"
#  ifdef READ_GIF
           " [-g name.gif]"
#  endif // READ_GIF
# endif  // READ_FILE
           "\n", argv[0]);
#endif  // !TINY
    exit(EXIT_FAILURE);
  }

  openlog("pixelserv", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
  syslog(LOG_INFO, "%s version: %s compiled: %s from %s", argv[0], VERSION, __DATE__ " " __TIME__ , __FILE__ );

#ifdef READ_FILE
  if (fname) {
    if ( stat(fname, &file_stat) < 0 ) {
      syslog(LOG_ERR, "stat: '%s': %m", fname);
      exit(EXIT_FAILURE);
    }

    fsize = (int) file_stat.st_size;
    TESTPRINT("fsize:%d\n", fsize);

    if (fsize < 43) {
      syslog(LOG_ERR, "%s: size only %d", fname, fsize);
      exit(EXIT_FAILURE);
    }

    if (( fp = fopen(fname, "rb") ) == NULL) {
      syslog(LOG_ERR, "fopen: '%s': %m", fname);
      exit(EXIT_FAILURE);
    }

# ifdef READ_GIF
    if (do_gif) {
      snprintf(buf, CHAR_BUF_SIZE,
        "HTTP/1.1 200 OK\r\n"
        "Content-type: image/gif\r\n"
        "Content-length: %d\r\n"
        "Connection: close\r\n"
        "\r\n", fsize);

      hsize = strlen(buf);
      TESTPRINT("hsize:%d\n", hsize);
    }
# endif

    rsize = hsize + fsize;
    TESTPRINT("rsize:%d\n", rsize);
    if ((response = malloc(rsize)) == NULL) {
      syslog(LOG_ERR, "malloc: %m");
      exit(EXIT_FAILURE);
    }

# ifdef READ_GIF
    if (do_gif) {
      strcpy( (char *) response, buf );
    }
# endif

    if (fread(&response[hsize], sizeof(char), fsize, fp) < fsize) {
      syslog(LOG_ERR, "fread: '%s': %m", fname);
      exit(EXIT_FAILURE);
    }

    fclose(fp);
  }
# ifdef SAVE_RESP
  fp = fopen("test.tmp", "wb");
  fwrite(response, sizeof(char), rsize, fp);
  fclose(fp);
# endif
#endif // READ_FILE

#ifndef TEST
  if ( daemon(0, 0) != OK ) {
    syslog(LOG_ERR, "failed to daemonize, exit: %m");
    exit(EXIT_FAILURE);
  }
#endif

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;  // AF_UNSPEC - AF_INET restricts to IPV4
  hints.ai_socktype = SOCK_STREAM;
  if (!use_ip) {
    hints.ai_flags = AI_PASSIVE;  // use my IP
  }

#ifdef PORT_MODE
  if (num_ports == 0) {
# ifdef MULTIPORT
    num_ports = 2;
# else
    num_ports = 1;
# endif
  }

  for (i = 0; i < num_ports; i++) {
    port = ports[i];
#endif

    rv = getaddrinfo(use_ip ? ip_addr : NULL, port, &hints, &servinfo);
    if (rv != OK) {
      syslog( LOG_ERR, "getaddrinfo: %s", gai_strerror(rv) );
      exit(EXIT_FAILURE);
    }

    if ( (( sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol) ) < 1)
      || ( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) != OK )
      || ( setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &yes, sizeof(int)) != OK )  /* send short packets straight away */
#ifdef IF_MODE
      || ( use_if && (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) != OK) )  /* only use selected i/f */
#endif
      || ( bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) != OK )
      || ( listen(sockfd, BACKLOG) != OK ) ) {
#ifdef IF_MODE
      syslog(LOG_ERR, "Abort: %m - %s %s:%s", ifname, ip_addr, port);
#else
      syslog(LOG_ERR, "Abort: %m - %s:%s", ip_addr, port);
#endif
      exit(EXIT_FAILURE);
    }
#ifdef PORT_MODE
#ifdef MULTIPORT
    sockfds[i] = sockfd;
  }
#endif
#endif

  freeaddrinfo(servinfo); /* all done with this structure */

  {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

#ifndef TINY
    /* set signal handler for termination */
    if ( sigaction(SIGTERM, &sa, NULL) != OK ) {
      syslog(LOG_ERR, "SIGTERM %m");
      exit(EXIT_FAILURE);
    }
#endif
    /* reap all dead processes */
    sa.sa_flags = SA_RESTART;
    if ( sigaction(SIGCHLD, &sa, NULL) != OK ) {
      syslog(LOG_ERR, "SIGCHLD %m");
      exit(EXIT_FAILURE);
    }
#ifdef DO_COUNT
    /* set signal handler for info */
    if ( sigaction(SIGUSR1, &sa, NULL) != OK ) {
      syslog(LOG_ERR, "SIGUSR1 %m");
      exit(EXIT_FAILURE);
    }
#endif
  }

#ifdef DROP_ROOT // no longer fatal error if doesn't work
  if ( (pw = getpwnam(user)) == NULL ) {
    syslog(LOG_WARNING, "Unknown user \"%s\"", user);
  }
  else if ( setuid(pw->pw_uid) ) {
    syslog( LOG_WARNING, "setuid %d: %s\n", pw->pw_uid, strerror(errno) );
  }
#endif


#ifdef MULTIPORT
  for (i = 0; i < num_ports; i++) {
    port = ports[i];
#endif

#ifdef IF_MODE
  syslog(LOG_NOTICE, "Listening on %s %s:%s", ifname, ip_addr, port);
#else
  syslog(LOG_NOTICE, "Listening on %s:%s", ip_addr, port);
#endif
#ifdef MULTIPORT
  }
#endif

  sin_size = sizeof their_addr;
  while(1) {  /* main accept() loop */
#ifdef MULTIPORT
    sockfd = 0;
    // clear the set
    FD_ZERO(&readfds);
    // add our descriptors to the set
    for (i = 0; i < num_ports; i++) {
      FD_SET(sockfds[i], &readfds);
    }

    // NOTE: MACRO needs "_GNU_SOURCE", without this the select gets interrupted with errno EINTR
    select_rv = TEMP_FAILURE_RETRY( select(FD_SETSIZE, &readfds, NULL, NULL, NULL) );
    if (select_rv < 0) {
      syslog(LOG_ERR, "select(fd) error: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }

    for (i = 0; i < num_ports; i++) {
      if ( FD_ISSET(sockfds[i], &readfds) ) {
        sockfd = sockfds[i];
        break;
      }
    }

    if (!sockfd) {
      continue;
    }
#endif
    new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &sin_size);
    if (new_fd < 1) {
      MYLOG(LOG_WARNING, "accept: %m");
      continue;
    }

#ifdef DO_COUNT
    count++;
#endif

    if ( fork() == 0 ) {
      /* this is the child process */
      close(sockfd); /* child doesn't need the listener */
#ifndef TINY
      signal(SIGTERM, SIG_DFL);
#endif
      signal(SIGCHLD, SIG_DFL);
#ifdef DO_COUNT
      signal(SIGUSR1, SIG_IGN);
#endif

#ifdef TEST
      inet_ntop(their_addr.ss_family, get_in_addr( (struct sockaddr *) &their_addr ), s, sizeof s);
      printf("server: got connection from %s\n", s);
#endif

#ifdef TEXT_REPLY
      /* read a line from the request */
      FD_ZERO(&set);
      FD_SET(new_fd, &set);
      /* Initialize the timeout data structure */
      timeout.tv_sec = 2;
      timeout.tv_usec = 0;

      /* select returns 0 if timeout, 1 if input available, -1 if error */
      select_rv = select(new_fd + 1, &set, NULL, NULL, &timeout);
      if (select_rv < 0) {
        MYLOG(LOG_ERR, "select: %m");
      } else if (select_rv == 0) {
        MYLOG(LOG_ERR, "timeout on select");
      } else {
        rv = recv(new_fd, buf, CHAR_BUF_SIZE, 0);
        if (rv < 0) {
          MYLOG(LOG_ERR, "recv: %m");
        } else if (rv == 0) {
          MYLOG(LOG_ERR, "recv: No data");
        } else {
          buf[rv] = '\0';
          TESTPRINT("\nreceived %d bytes\n'%s'\n", rv, buf);
# ifdef HEX_DUMP
          hex_dump(buf, rv);
# endif
# ifdef SSL_RESP
          if (buf[0] == '\x16'){
            TESTPRINT("SSL handshake request received\n");
            status = SEND_SSL;
            response = SSL_no;
            rsize = sizeof SSL_no - 1;
          } else {
# endif
            char *method = strtok(buf, " ");
            if (method == NULL) {
              MYLOG(LOG_ERR, "null method");
            } else {
              TESTPRINT("method: '%s'\n", method);
              if ( strcmp(method, "GET") ) {  //methods are case-sensitive
                MYLOG(LOG_ERR, "unknown method: %s", method);
                status = SEND_BAD;
                TESTPRINT("Sending 501 response\n");
                response = http501;
                rsize = sizeof http501 - 1;
              } else {
                status = DEFAULT_REPLY;  // send default from here
                /* trim up to non path chars */
#ifdef REDIRECT
                char *path = strtok(NULL, " ");//, " ?#;=");     // "?;#:*<>[]='\"\\,|!~()"
#else
                char *path = strtok(NULL, " ?#;=");	// "?;#:*<>[]='\"\\,|!~()"
#endif // REDIRECT
                if (path == NULL) {
                  MYLOG(LOG_ERR, "null path");
                } else {
#ifdef REDIRECT
                  /* pick out encoded urls (usually advert redirects) */
                  if (do_redirect && strstr(path, "=http") && strchr(path, '%')) {
                    char *decoded = malloc(strlen(path)+1);
                    urldecode(decoded, path);
                    /* double decode */
                    urldecode(path, decoded);
                    free(decoded);
                    url = strstr_last(path, "http://");
                    if (url == NULL) {
                      url = strstr_last(path, "https://");
                    }
                    /* WORKAROUND: google analytics block - request bomb on pages with conversion callbacks (see in chrome) */
                    if (url) {
                      char *tok = NULL;
                      bufptr = NULL;
                      for (tok = strtok_r(path, "\r\n", &bufptr); tok; tok = strtok_r(NULL, "\r\n", &bufptr)) {
                        char *hkey = strtok(tok, ":");
                        char *hvalue = strtok(NULL, "\r\n");
                        if (strstr(hkey, "Referer") && strstr(hvalue, url)) {
                          url = NULL;
                          TESTPRINT("Not redirecting likely callback URL: %s:%s\n", hkey, hvalue);
                        }
                      }
                    }
                  }
                  if (do_redirect && url) {
                    location = NULL;
                    status = SEND_REDIRECT;
                    rsize = asprintf(&location, httpredirect, url);
                    response = (unsigned char *)(location);
                    TESTPRINT("Sending redirect: %s\n", url);
                    url = NULL;
                  } else {
                    char *file = strrchr(strtok(path, "?#;="), '/');
#else
                    TESTPRINT("path: '%s'\n",path);
                    char *file = strrchr(path, '/');
#endif // REDIRECT
                    if (file == NULL) {
                      MYLOG(LOG_ERR, "invalid file path %s", path);
                    } else {
                      TESTPRINT("file: '%s'\n", file);
                      char *ext = strrchr(file, '.');
                      if (ext == NULL) {
                        MYLOG(LOG_ERR, "No file extension %s", file);
                      } else {
                        TESTPRINT("ext: '%s'\n", ext);
# ifdef NULLSERV_REPLIES
                        if ( !strcasecmp(ext, ".gif") ) {
                          TESTPRINT("Sending gif response\n");
                          status = SEND_GIF;
                          response = httpnullpixel;
                          rsize = sizeof httpnullpixel - 1;
                        } else if (!strcasecmp(ext, ".png") ) {
                          TESTPRINT("Sending png response\n");
                          status = SEND_PNG;
                          response = httpnull_png;
                          rsize = sizeof httpnull_png - 1;
                        } else if (!strncasecmp(ext, ".jp", 3) ) {
                          TESTPRINT("Sending jpg response\n");
                          status = SEND_JPG;
                          response = httpnull_jpg;
                          rsize = sizeof httpnull_jpg - 1;
                        } else if (!strcasecmp(ext, ".swf") ) {
                          TESTPRINT("Sending swf response\n");
                          status = SEND_SWF;
                          response = httpnull_swf;
                          rsize = sizeof httpnull_swf - 1;
                        }
# else
                        if ( !strncasecmp(ext, ".js", 3) ) {  /* .jsx ?*/
                          status = SEND_TXT;
                          TESTPRINT("Sending Txt response\n");
                          response = httpnulltext;
                          rsize = sizeof httpnulltext - 1;
                        }
# endif
                      /* add other response types here */
# ifdef REDIRECT
                      }
# endif // REDIRECT
                    }
                  }
                }
              }
# ifdef SSL_RESP
            }
# endif
          }
        }
      }

      if (status != EXIT_FAILURE) {
#else  // TEXT_REPLY
      {
        status = SEND_GIF;
        TESTPRINT("Sending a gif response\n");
#endif  // TEXT_REPLY
        rv = send(new_fd, response, rsize, 0);

        /* check for error message, but don't bother checking that all bytes sent */
        if (rv < 0) {
          MYLOG(LOG_WARNING, "send: %m");
          status = EXIT_FAILURE;
        }
      }

      /* clean way to flush read buffers and close connection */
      if (shutdown(new_fd, SHUT_WR) == OK) {
        do {
          /* Initialize the file descriptor set */
          FD_ZERO(&set);
          FD_SET(new_fd, &set);
          /* Initialize the timeout data structure */
          timeout.tv_sec = 2;
          timeout.tv_usec = 0;
          /* select returns 0 if timeout, 1 if input available, -1 if error */
          select_rv = select(new_fd + 1, &set, NULL, NULL, &timeout);
        } while ( (select_rv > 0) && ( recv(new_fd, buf, CHAR_BUF_SIZE, 0) > 0 ) );
      }

      shutdown(new_fd, SHUT_RD);
      close(new_fd);
      exit(status);
    }

    close(new_fd);  // parent doesn't need this
  }
//  Never get here while(1)
//  return (EXIT_SUCCESS);
}

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
V35.HZ1 merge in a bunch of h0tw1r3 changes (mainly REDIRECT feature) in attempt to bring the forks back together
*/
