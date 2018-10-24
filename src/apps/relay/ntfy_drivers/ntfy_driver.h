/* 
 * File:   ntfy_driver.h
 * Author: islamoglus
 *
 * Created on October 16, 2018, 4:43 PM
 */

#ifndef NTFY_DRIVER_H
#define NTFY_DRIVER_H

#include"../../../ns_turn_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  TURN_NTFY_LEVEL_INFO = 0,
  TURN_NTFY_LEVEL_CONTROL,
  TURN_NTFY_LEVEL_WARNING,
  TURN_NTFY_LEVEL_ERROR
} TURN_NTFY_LEVEL;

extern pthread_key_t notifier_key;
extern pthread_once_t notifier_key_once;

typedef void* subs_long_term_data_t;

typedef struct _turn_ntfy_subscriber_if_t {
  s08bits* name;
  subs_long_term_data_t long_term_data;
  subs_long_term_data_t (*init)(void);
  int (*notify)( subs_long_term_data_t, TURN_NTFY_LEVEL, const s08bits*);
  int (*remove)( subs_long_term_data_t);
} turn_ntfy_subscriber_if_t;

#define TURN_NTFY_CHECK (turn_ntfy_check())
#define TURN_NTFY_FUNC turn_ntfy_func_default

int turn_ntfy_check(void);
void turn_ntfy_func_default(TURN_NTFY_LEVEL level, const s08bits* format, ...);

#ifdef __cplusplus
}
#endif

#endif /* NTFY_DRIVER_H */
