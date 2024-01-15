#include "ns_turn_utils.h"
#include <log4cplus/clogger.h>
#include <log4cplus/helpers/snprintf.h>
#include <log4cplus/logger.h>

using namespace log4cplus;
using namespace log4cplus::helpers;

void *turn_log_init() {
  int ret = -1;
  void *log = log4cplus_initialize();
  const char *file = "../etc/turnserver_log.conf";
  FILE *pf = fopen(file, "a");
  if (pf) {
    fclose(pf);
    ret = log4cplus_file_configure(file);
  }
  if (ret)
    log4cplus_basic_reconfigure(1);
  return log;
}

void turn_log_clean(void *log) { log4cplus_deinitialize(log); }

int turn_log_set_conf_file(const char *file) { return log4cplus_file_reconfigure(file); }

LogLevel turn_level_to_loglevel(TURN_LOG_LEVEL level) {
  switch ((int)level) {
  case TURN_LOG_LEVEL_DEBUG:
    return DEBUG_LOG_LEVEL;
  case TURN_LOG_LEVEL_INFO:
    return INFO_LOG_LEVEL;
  case TURN_LOG_LEVEL_WARNING:
    return WARN_LOG_LEVEL;
  case TURN_LOG_LEVEL_ERROR:
    return ERROR_LOG_LEVEL;
  }
  return DEBUG_LOG_LEVEL;
}

void turn_log_func_default(const char *file, int line, const char *f, char *category, TURN_LOG_LEVEL level,
                           const char *msgfmt, ...) {
  int retval = -1;

  try {
    Logger logger = category ? Logger::getInstance(category) : Logger::getRoot();
    LogLevel ll = turn_level_to_loglevel(level);

    if (logger.isEnabledFor(ll)) {
      const tchar *msg = nullptr;
      snprintf_buf buf;
      std::va_list ap;

      do {
        va_start(ap, msgfmt);
        retval = buf.print_va_list(msg, msgfmt, ap);
        va_end(ap);
      } while (retval == -1);

      logger.forcedLog(ll, msg, file, line, f);
    }

  } catch (std::exception const &e) {
    // Fall through.
    printf("logger.forcedLog exception: %s", e.what());
  }

  return;
}
