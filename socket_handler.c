#include "util.h"
#include "socket_handler.h"

// private data for socket_handler() use
#ifdef STATS_REPLY
  // HTML response pieces
  static const unsigned char httpstats1[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html\r\n"
  "Content-length: ";
  // total content length goes between these two strings
  static const unsigned char httpstats2[] =
  "\r\n"
  "Connection: close\r\n"
  "\r\n";
  // split here because we care about the length of what follows
  static const unsigned char httpstats3[] =
  "<!DOCTYPE html><html><head><title>pixelserv statistics</title></head><body>";
  // stats text goes between these two strings
  static const unsigned char httpstats4[] =
  "</body></html>\r\n";

  // note: the -2 is to avoid counting the last line ending characters
  static const unsigned int statsbaselen = sizeof httpstats3 + sizeof httpstats4 - 2;

  // TXT response pieces
  static const unsigned char txtstats1[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/plain\r\n"
  "Content-length: ";
  // total content length goes between these two strings
  static const unsigned char txtstats2[] =
  "\r\n"
  "Connection: close\r\n"
  "\r\n";
  // split here because we care about the length of what follows
  static const unsigned char txtstats3[] =
  "\r\n";
#endif

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
  "\xff\xd8"  // SOI, Start Of Image
  "\xff\xe0"  // APP0
  "\x00\x10"  // length of section 16
  "JFIF\0"
  "\x01\x01"  // version 1.1
  "\x01"      // pixel per inch
  "\x00\x48"  // horizontal density 72
  "\x00\x48"  // vertical density 72
  "\x00\x00"  // size of thumbnail 0 x 0
  "\xff\xdb"  // DQT
  "\x00\x43"  // length of section 3+64
  "\x00"      // 0 QT 8 bit
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xff\xff\xff\xff\xff\xff\xff"
  "\xff\xc0"  // SOF
  "\x00\x0b"  // length 11
  "\x08\x00\x01\x00\x01\x01\x01\x11\x00"
  "\xff\xc4"  // DHT Define Huffman Table
  "\x00\x14"  // length 20
  "\x00\x01"  // DC table 1
  "\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x03"
  "\xff\xc4"  // DHT
  "\x00\x14"  // length 20
  "\x10\x01"  // AC table 1
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

static unsigned char httpnull_ico[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: image/x-icon\r\n"
  "Cache-Control: max-age=2592000\r\n"
  "Content-length: 70\r\n"
  "Connection: close\r\n"
  "\r\n"
  "\x00\x00" // reserved 0
  "\x01\x00" // ico
  "\x01\x00" // 1 image
  "\x01\x01\x00" // 1 x 1 x >8bpp colour
  "\x00" // reserved 0
  "\x01\x00" // 1 colour plane
  "\x20\x00" // 32 bits per pixel
  "\x30\x00\x00\x00" // size 48 bytes
  "\x16\x00\x00\x00" // start of image 22 bytes in
  "\x28\x00\x00\x00" // size of DIB header 40 bytes
  "\x01\x00\x00\x00" // width
  "\x02\x00\x00\x00" // height
  "\x01\x00" // colour planes
  "\x20\x00" // bits per pixel
  "\x00\x00\x00\x00" // no compression
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00" // end of header
  "\x00\x00\x00\x00" // Colour table
  "\x00\x00\x00\x00" // XOR B G R
  "\x80\xF8\x9C\x41"; // AND ?
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

// private functions for socket_handler() use
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
#endif // HEX_DUMP

#ifdef REDIRECT
// redirect utility functions
char* strstr_last(const char *str1, const char *str2) {
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

int socket_handler(int new_fd
                  ,time_t select_timeout
#ifdef STATS_PIPE
                  ,int pipefd
#endif
#ifdef STATS_REPLY
                  ,char* stats_url
                  ,char* stats_text_url
                  ,char* program_name
#endif
#ifdef REDIRECT
                  ,int do_redirect
#endif
#ifdef READ_FILE
                  ,unsigned char* default_response
                  ,int default_rsize
#endif
                  ) {
  // NOTES:
  // - from here on, all exit points should be counted or at least logged
  // - something MUST be written to the pipe before any exit point to prevent
  //   the parent thread's read() from hanging forever
  // - a value of -1 should be written to the pipe if exit() is called without
  //   having read anything from the socket connection
  // - exit() should not be called from the child process
  fd_set select_set;
  struct timeval timeout;
  int select_rv;
  int status = EXIT_FAILURE; /* default return from child */
  int rv;
  char buf[CHAR_BUF_SIZE + 1];
#ifdef STATS_PIPE
  int rx_total = -1;
#endif
#ifdef REDIRECT
  char *bufptr = NULL;
  char *url = NULL;
  char *location = NULL;
#endif

#ifdef NULLSERV_REPLIES
# define DEFAULT_REPLY SEND_TXT
  unsigned char *response = httpnulltext;
  int rsize = sizeof httpnulltext - 1;
#else
# define DEFAULT_REPLY SEND_GIF
  unsigned char *response = httpnullpixel;
  int rsize = sizeof httpnullpixel - 1;
#endif

#ifdef READ_FILE
  // if default_response is non-NULL, then a command line override was provided
  if (default_response != NULL) {
    response = default_response;
    rsize = default_rsize;
  }
#endif

#ifdef TEXT_REPLY
  /* read a line from the request */
  FD_ZERO(&select_set);
  FD_SET(new_fd, &select_set);
  /* Initialize the timeout data structure */
  timeout.tv_sec = select_timeout;
  timeout.tv_usec = 0;

  /* select returns 0 if timeout, 1 if input available, -1 if error */
  select_rv = select(new_fd + 1, &select_set, NULL, NULL, &timeout);
  if (select_rv < 0) {
    syslog(LOG_ERR, "select() returned error: %m");
  } else if (select_rv == 0) {
    MYLOG(LOG_ERR, "select() timed out");
    status = FAIL_TIMEOUT;
  } else {
    rv = recv(new_fd, buf, CHAR_BUF_SIZE, 0);
    if (rv < 0) {
      syslog(LOG_ERR, "recv() returned error: %m");
    } else if (rv == 0) {
      status = FAIL_CLOSED;
      MYLOG(LOG_ERR, "client closed connection without sending any data");
    } else {
      buf[rv] = '\0';
      TESTPRINT("\nreceived %d bytes\n'%s'\n", rv, buf);
# ifdef STATS_PIPE
      rx_total = rv;  // record number of bytes read so far during this loop pass
# endif
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
# ifdef REDIRECT
        char *req = strtok_r(buf, "\r\n", &bufptr);
        char *method = strtok(req, " ");
# else
        char *method = strtok(buf, " ");
# endif
        if (method == NULL) {
          syslog(LOG_ERR, "client did not specify method");
        } else {
          TESTPRINT("method: '%s'\n", method);
          if ( strcmp(method, "GET") ) {  //methods are case-sensitive
            MYLOG(LOG_ERR, "unknown method: %s", method);
            status = SEND_BAD;
            TESTPRINT("Sending 501 response\n");
            response = http501;
            rsize = sizeof http501 - 1;
          } else {
            // ----------------------------------------------
            // send default from here, no matter what happens
            status = DEFAULT_REPLY;
            /* trim up to non path chars */
# ifdef REDIRECT
            char *path = strtok(NULL, " ");//, " ?#;=");     // "?;#:*<>[]='\"\\,|!~()"
# else
            char *path = strtok(NULL, " ?#;="); // "?;#:*<>[]='\"\\,|!~()"
# endif // REDIRECT
            if (path == NULL) {
              status = SEND_NO_URL;
              syslog(LOG_ERR, "client did not specify URL for GET request");
# ifdef STATS_REPLY
            } else if (!strcmp(path, stats_url)) {
              status = SEND_STATS;
              char* version_string = get_version(program_name);
              char* stat_string = get_stats(1, 0);
              asprintf((char**)(&response),
                       "%s%d%s%s%s<br>%s%s",
                       httpstats1,
                       statsbaselen + strlen(version_string) + 4 + strlen(stat_string),
                       httpstats2,
                       httpstats3,
                       version_string,
                       stat_string,
                       httpstats4);
              free(version_string);
              free(stat_string);
              rsize = strlen((char*)response);
            } else if (!strcmp(path, stats_text_url)) {
              status = SEND_STATSTEXT;
              char* version_string = get_version(program_name);
              char* stat_string = get_stats(0, 1);
              asprintf((char**)(&response),
                       "%s%d%s%s\n%s%s",
                       txtstats1,
                       strlen(version_string) + 1 + strlen(stat_string) + 2,
                       txtstats2,
                       version_string,
                       stat_string,
                       txtstats3);
              free(version_string);
              free(stat_string);
              rsize = strlen((char*)response);
# endif
            } else {
# ifdef REDIRECT
              /* pick out encoded urls (usually advert redirects) */
//                  if (do_redirect && strstr(path, "=http") && strchr(path, '%')) {
              if (do_redirect && strcasestr(path, "=http")) {
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
                  for (tok = strtok_r(NULL, "\r\n", &bufptr); tok; tok = strtok_r(NULL, "\r\n", &bufptr)) {
                    char *hkey = strtok(tok, ":");
                    char *hvalue = strtok(NULL, "\r\n");
                    if (strstr(hkey, "Referer") && strstr(hvalue, url)) {
                      url = NULL;
                      TESTPRINT("Not redirecting likely callback URL: %s:%s\n", hkey, hvalue);
                      break;
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
# else
                TESTPRINT("path: '%s'\n",path);
                char *file = strrchr(path, '/');
# endif // REDIRECT
                if (file == NULL) {
                  status = SEND_BAD_PATH;
                  syslog(LOG_ERR, "invalid file path %s", path);
                } else {
                  TESTPRINT("file: '%s'\n", file);
                  char *ext = strrchr(file, '.');
                  if (ext == NULL) {
                    status = SEND_NO_EXT;
                    MYLOG(LOG_ERR, "no file extension %s from path %s", file, path);
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
                    } else if (!strcasecmp(ext, ".ico") ) {
                      status = SEND_ICO;
                      response = httpnull_ico;
                      rsize = sizeof httpnull_ico - 1;
                    } else {
                      status = SEND_UNK_EXT;
                      MYLOG(LOG_ERR, "unrecognized file extension %s from path %s", ext, path);
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

  if (status == EXIT_FAILURE) {
    syslog(LOG_WARNING, "browser request processing completed with EXIT_FAILURE status");
  } else if (status != FAIL_TIMEOUT && status != FAIL_CLOSED) {
#else  // TEXT_REPLY
  {
    status = SEND_GIF;
    TESTPRINT("Sending a gif response\n");
#endif  // TEXT_REPLY
    rv = send(new_fd, response, rsize, 0);
#ifdef STATS_REPLY
    if (status == SEND_STATS || status == SEND_STATSTEXT) {
      // free memory allocated by asprintf()
      free(response);
      response = NULL;
    }
#endif // STATS_REPLY
#ifdef REDIRECT
    if (status == SEND_REDIRECT) {
      // free memory allocated by asprintf()
      free(location);
      location = NULL;
      response = NULL;
    }
#endif // REDIRECT
    /* check for error message, but don't bother checking that all bytes sent */
    if (rv < 0) {
      MYLOG(LOG_WARNING, "send: %m");
      syslog(LOG_ERR, "attempt to send response for status=%d resulted in send() error: %m", status);
      status = EXIT_FAILURE;
    }
  }

  /* clean way to flush read buffers and close connection */
  if (shutdown(new_fd, SHUT_WR) == OK) {
    do {
      /* Initialize the file descriptor set */
      FD_ZERO(&select_set);
      FD_SET(new_fd, &select_set);
      /* Initialize the timeout data structure */
      timeout.tv_sec = select_timeout;
      timeout.tv_usec = 0;
      /* select returns 0 if timeout, 1 if input available, -1 if error */
      select_rv = select(new_fd + 1, &select_set, NULL, NULL, &timeout);
      if (select_rv > 0) {
        rv = recv(new_fd, buf, CHAR_BUF_SIZE, 0);
#ifdef STATS_PIPE
        if (rv > 0) {
          rx_total += rv;
        }
#endif
      }
    } while (select_rv > 0 && rv > 0);
  }

  shutdown(new_fd, SHUT_RD);
  close(new_fd);

#ifdef STATS_PIPE
  // write rx_total to pipe
  if (write(pipefd, &rx_total, sizeof(rx_total)) < 0) {
    // log as warning only because it only affects stats
    syslog(LOG_WARNING, "write() to pipe returned error: %m");
    // should probably also check for return value of 0 and of != sizeof(rx_total)...
  }
  close(pipefd);
#endif

  if (status == EXIT_FAILURE) {
    syslog(LOG_WARNING, "connection handler exiting with EXIT_FAILURE status");
  }

  return status;
}
