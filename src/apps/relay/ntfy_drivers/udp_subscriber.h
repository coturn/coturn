/* 
 * File:   udp_subscriber.h
 * Author: islamoglus
 *
 * Created on October 17, 2018, 2:11 PM
 */

#ifndef UDP_SUBSCRIBER_H
#define UDP_SUBSCRIBER_H

#include"ntfy_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

int udp_subscriber_flag(void);
turn_ntfy_subscriber_if_t* udp_subscriber_inferface_get(void);

#ifdef __cplusplus
}
#endif

#endif /* UDP_SUBSCRIBER_H */
