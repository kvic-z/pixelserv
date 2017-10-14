#ifndef LOGGER_H
#define LOGGER_H

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

#endif