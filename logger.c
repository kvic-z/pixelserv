#include <stdarg.h>
#include <syslog.h>
#include "logger.h"

#ifndef DEBUG
static logger_level _verb = LGG_ERR;
#else
static logger_level _verb = LGG_DEBUG;
#endif

void log_set_verb(logger_level verb) { _verb = verb; }
logger_level log_get_verb() { return _verb; }

void log_msg(int verb, char *fmt, ...)
{
    if (verb > _verb)
      return;
      
    va_list args;
    va_start(args, fmt);
    vsyslog(LOG_CRIT + verb, fmt, args);
    va_end(args);
}