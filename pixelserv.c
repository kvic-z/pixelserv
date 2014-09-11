/*
* pixelserv.c a small mod to public domain server.c -- a stream socket server demo
* from http://beej.us/guide/bgnet/
* single pixel http string from http://proxytunnel.sourceforge.net/pixelserv.php
*/

#include "util.h"
#include "socket_handler.h"

#ifdef READ_FILE
# include <sys/stat.h>
#endif

void signal_handler(int sig)
{
  int status;
  switch (sig) {
  case SIGCHLD :  // ensure no zombie sub processes left */
    while ( waitpid(-1, &status, WNOHANG) > 0 ) {
#ifdef DO_COUNT
      if ( WIFEXITED(status) ) {
        switch ( WEXITSTATUS(status) ) {
          case EXIT_FAILURE:   err++; break;
          case FAIL_TIMEOUT:   tmo++; break;
          case FAIL_CLOSED:    cls++; break;
          case SEND_NO_URL:    nou++; break;
          case SEND_BAD_PATH:  pth++; break;
          case SEND_NO_EXT:    nfe++; break;
          case SEND_UNK_EXT:   ufe++; break;
          case SEND_GIF:       gif++; break;
# ifdef STATS_REPLY
          case SEND_STATS:     sta++; break;
          case SEND_STATSTEXT: stt++; break;
# endif // STATS_REPLY
# ifdef REDIRECT
          case SEND_REDIRECT:  rdr++; break;
# endif // REDIRECT
# ifdef TEXT_REPLY
          case SEND_BAD:       bad++; break;
          case SEND_TXT:       txt++; break;
#  ifdef NULLSERV_REPLIES
          case SEND_JPG:       jpg++; break;
          case SEND_PNG:       png++; break;
          case SEND_SWF:       swf++; break;
          case SEND_ICO:       ico++; break;
#  endif  // NULLSERV_REPLIES
#  ifdef SSL_RESP
          case SEND_SSL:       ssl++; break;
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
    {
      char* stats_string = get_stats(0, 0);
      syslog(LOG_INFO, "%s", stats_string);
      free(stats_string);
    }

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
// get sockaddr, IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa)
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
  char ntop_buf[INET6_ADDRSTRLEN];
#endif
  time_t select_timeout = DEFAULT_TIMEOUT;
  int rv;
  char *ip_addr = DEFAULT_IP;
  int use_ip = 0;
#ifdef STATS_PIPE
  int pipefd[2];  // IPC pipe ends (0 = read, 1 = write)
  int rx_total = -1;
#endif

#ifdef PORT_MODE
  char *ports[MAX_PORTS];
  ports[0] = DEFAULT_PORT;
  char *port;
# ifdef MULTIPORT
  fd_set readfds;
  int sockfds[MAX_PORTS];
  ports[1] = SECOND_PORT;
  int select_rv;
# endif
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

#ifdef STATS_REPLY
  char* stats_url = DEFAULT_STATS_URL;
  char* stats_text_url = DEFAULT_STATS_TEXT_URL;
#endif

#ifdef REDIRECT
  int do_redirect = 0;
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
  unsigned char *response = NULL;
  int rsize = -1;
  char buf[CHAR_BUF_SIZE + 1];
#endif // READ_FILE

  struct addrinfo hints, *servinfo;
  int error = 0;

  /* command line arguments processing */
  for (i = 1; i < argc && error == 0; ++i) {
    if (argv[i][0] == '-') {
#ifdef REDIRECT
      if (argv[i][1] == 'r') { // doesn't require a subsequent argument
        do_redirect = 1;
        continue;
      }
#endif
      if ( (i + 1) < argc ) { // arguments that require a subsequent argument
        switch (argv[i][1]) {
#ifdef IF_MODE
        case 'n' :
          ifname = argv[++i];
          use_if = 1;
          break;
#endif
        case 'o' :
          errno = 0;
          select_timeout = strtol(argv[++i], NULL, 10);
          if (errno) {
            ++i;
            error = 1;
          }
          break;
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
#ifdef STATS_REPLY
        case 's' :
          stats_url = argv[++i];
          break;
        case 't' :
          stats_text_url = argv[++i];
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
      } else {
        error = 1;
      }
    } else if (use_ip == 0) {  // assume its a listening IP address
      ip_addr = argv[i];
      use_ip = 1;
    } else {
      error = 1;  // fix bug with 2 IP like args
    } // -
  } // for

  if (error) {
#ifndef TINY
    printf("Usage:%s"
           " [IP No/hostname (all)]"
# ifdef IF_MODE
           " [-n i/f (all)]"
# endif // IF_MODE
           " [-o select_timeout (%d seconds)]"
# ifdef PORT_MODE
           " [-p port ("
           DEFAULT_PORT
           ")"
#  ifdef MULTIPORT
           " & ("
           SECOND_PORT
           ")"
#  endif
           "]"
# endif
# ifdef REDIRECT
           " [-r (enables redirect to encoded path in tracker links)]"
# endif // REDIRECT
# ifdef STATS_REPLY
           " [-s /relative_stats_html_URL ("
           DEFAULT_STATS_URL
           ")"
           " [-t /relative_stats_txt_URL ("
           DEFAULT_STATS_TEXT_URL
           ")"
# endif // STATS_REPLY
# ifdef DROP_ROOT
           " [-u user (\"nobody\")]"
# endif // DROP_ROOT
# ifdef READ_FILE
           " [-f response.bin]"
#  ifdef READ_GIF
           " [-g name.gif]"
#  endif // READ_GIF
# endif  // READ_FILE
           "\n", argv[0], DEFAULT_TIMEOUT);
#endif  // !TINY
    exit(EXIT_FAILURE);
  }

  openlog("pixelserv", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
  char* version_string = get_version(argv[0]);
  syslog(LOG_INFO, "%s", version_string);
  free(version_string);

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
      syslog(LOG_ERR, "Abort: %m - %s:%s:%s", ifname, ip_addr, port);
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
    syslog( LOG_WARNING, "setuid %d: %m", pw->pw_uid);
  }
#endif

#ifdef MULTIPORT
  for (i = 0; i < num_ports; i++) {
    port = ports[i];
#endif

#ifdef IF_MODE
  syslog(LOG_NOTICE, "Listening on %s:%s:%s", ifname, ip_addr, port);
#else
  syslog(LOG_NOTICE, "Listening on %s:%s", ip_addr, port);
#endif
#ifdef MULTIPORT
  }
#endif

#ifdef STATS_PIPE
  if (pipe(pipefd) == -1) {
    syslog(LOG_ERR, "pipe() error: %m");
    exit(EXIT_FAILURE);
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
      syslog(LOG_ERR, "select(fd) error: %m");
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
      // this is the child process

      // set child signal behavior
#ifndef TINY
      signal(SIGTERM, SIG_DFL);
#endif
      signal(SIGCHLD, SIG_DFL);
#ifdef DO_COUNT
      signal(SIGUSR1, SIG_IGN);
#endif
      // close unneeded file handles inherited from the parent process
      close(sockfd);
#ifdef STATS_PIPE
      close(pipefd[0]);
#endif
#ifdef TEST
      inet_ntop(their_addr.ss_family, get_in_addr( (struct sockaddr *) &their_addr ), ntop_buf, sizeof ntop_buf);
      printf("server: got connection from %s\n", ntop_buf);
#endif
      // call handler function and exit from child process with its return code
      exit(socket_handler(new_fd
                         ,select_timeout
#ifdef STATS_PIPE
                         ,pipefd[1]
#endif
#ifdef STATS_REPLY
                         ,stats_url
                         ,stats_text_url
                         ,argv[0]
#endif
#ifdef REDIRECT
                         ,do_redirect
#endif
#ifdef READ_FILE
                         ,response
                         ,rsize
#endif // READ_FILE
                         ));
    } // end of forked child process

    // this is guaranteed to be the parent process, as the child calls exit()
    //  above when it's done instead of proceeding to this point
    close(new_fd);  // parent doesn't need this

#ifdef STATS_PIPE
    // NOTE: do NOT close write end of pipe, because next child will need it to
    //       still be open
    //
    // perform a single read from pipe, which will block until the child has
    //  written something (unless it already has)
    rv = read(pipefd[0], &rx_total, sizeof(rx_total));
    if (rv < 0) {
      syslog(LOG_ERR, "error reading from pipe: %m");
    } else if (rv == 0) {
      syslog(LOG_ERR, "pipe read() returned zero");
    } else if (rv != sizeof(rx_total)) {
      syslog(LOG_WARNING, "pipe read() got %d bytes, but %d bytes were expected - discarding", rv, sizeof(rx_total));
    } else if (rx_total < 0) {
      syslog(LOG_WARNING, "pipe read() got negative data value %d - discarding", rx_total);
    } else {
      // calculate as a double, round up, truncate to int
      avg += ((double)(rx_total - avg) / ++act) + 0.5;
      if (rx_total > rmx) {
        rmx = rx_total;
      }
    }
#endif
  } // end of perpetual accept() loop
//  Never get here while(1)
//  return (EXIT_SUCCESS);
}
