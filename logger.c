#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include "logger.h"

#ifndef DEBUG
static logger_level _verb = LGG_ERR;
#else
static logger_level _verb = LGG_DEBUG;
#endif

static int ctrl_char(char *buf, int len) {
    if (strlen(buf) < len)
        return 1;
    int i;
    for (i=0; i<len; i++)
        if (buf[i] < 32)
            return 1;
    return 0;
}

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

void log_xcs(int verb, char *client_ip, char *host, int tls, char *req, char *body, int body_len)
{
    if (verb > _verb)
      return;

    if (strlen(req) < MAX_LOG_CHUNK_SIZE)
        syslog(LOG_CRIT + verb, "%s %s %s%s", client_ip, host, req, tls ? " secure" : "");
    else {
        int num_chunks = strlen(req) / MAX_LOG_CHUNK_SIZE + 1;
        char store = req[MAX_LOG_CHUNK_SIZE];
        req[MAX_LOG_CHUNK_SIZE] = '\0';
        syslog(LOG_CRIT + verb, "%s %s %s", client_ip, host, req);
        req[MAX_LOG_CHUNK_SIZE] = store;

        int chunk = 1;
        if (num_chunks > 2)
          for (; chunk < num_chunks - 1; chunk++) {
              store = req[MAX_LOG_CHUNK_SIZE * (chunk + 1)];
              req[MAX_LOG_CHUNK_SIZE * (chunk + 1)] = '\0';
              syslog(LOG_CRIT + verb, "%s", req + MAX_LOG_CHUNK_SIZE * chunk);
              req[MAX_LOG_CHUNK_SIZE * (chunk + 1)] = store;
          }
        syslog(LOG_CRIT + verb, "%s%s", req + MAX_LOG_CHUNK_SIZE * chunk, tls ? " secure" : "");
    }

    if (body_len > 0 && body) {
      if (ctrl_char(body, body_len))
          syslog(LOG_CRIT + verb, "[%s]", "-binary POST content not dumped-");
      else if (strlen(body) < MAX_LOG_CHUNK_SIZE)
          syslog(LOG_CRIT + verb, "[%s]", body);
      else {
          int num_chunks = strlen(body) / MAX_LOG_CHUNK_SIZE + 1;
          char store = body[MAX_LOG_CHUNK_SIZE];
          body[MAX_LOG_CHUNK_SIZE] = '\0';
          syslog(LOG_CRIT + verb, "[%s", body);
          body[MAX_LOG_CHUNK_SIZE] = store;

          int chunk = 1;
          if (num_chunks > 2)
            for (; chunk < num_chunks - 1; chunk++) {
                store = body[MAX_LOG_CHUNK_SIZE * (chunk + 1)];
                body[MAX_LOG_CHUNK_SIZE * (chunk + 1)] = '\0';
                syslog(LOG_CRIT + verb, "%s", body + MAX_LOG_CHUNK_SIZE * chunk);
                body[MAX_LOG_CHUNK_SIZE * (chunk + 1)] = store;
            }
          syslog(LOG_CRIT + verb, "%s]", body + MAX_LOG_CHUNK_SIZE * chunk);
      }
    }
}
