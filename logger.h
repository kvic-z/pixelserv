#ifndef LOGGER_H
#define LOGGER_H

#define MAX_LOG_CHUNK_SIZE  8000   /* size of chunk output to logging facility each time */

typedef enum {    
    LGG_CRIT = 0,
    LGG_ERR,
    LGG_WARNING,
    LGG_NOTICE,
    LGG_INFO,
    LGG_DEBUG
} logger_level;

void log_set_verb(logger_level verb);
logger_level log_get_verb();
void log_msg(int verb, char *fmt, ...);
void log_xcs(int verb, char *client_ip, char *host, int tls, char *req, char *body);

#endif
