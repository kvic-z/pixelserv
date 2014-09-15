#ifndef SOCKET_HANDLER_H
#define SOCKET_HANDLER_H

typedef enum {
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
} responsetypes;

responsetypes socket_handler(const int new_fd
                            ,const time_t select_timeout
#ifdef STATS_PIPE
                            ,const int pipefd
#endif
#ifdef STATS_REPLY
                            ,const char* const stats_url
                            ,const char* const stats_text_url
                            ,const char* const program_name
#endif
#ifdef REDIRECT
                            ,const int do_redirect
#endif
#ifdef READ_FILE
                            ,const char* const default_response
                            ,const int default_rsize
#endif
                            );

#endif // SOCKET_HANDLER_H
