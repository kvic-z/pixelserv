#ifndef SOCKET_HANDLER_H
#define SOCKET_HANDLER_H

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
                  );

#endif // SOCKET_HANDLER_H
