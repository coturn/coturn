#include "ntfy_driver.h"
#include"../mainrelay.h"
#include "../../common/apputils.h"
#include "udp_subscriber.h"
#include "apps/relay/mainrelay.h"


typedef struct _turn_notifier_t{
    turn_ntfy_subscriber_if_t** subscribers;
    size_t subscriber_count;
}turn_notifier_t;


pthread_key_t notifier_key;
pthread_once_t notifier_key_once = PTHREAD_ONCE_INIT;

static void notifier_interface_remove(void*notifier_p);


static void make_notifier_key(void)
{
    (void) pthread_key_create(&notifier_key, notifier_interface_remove);
}

static void subscriber_add(turn_notifier_t* notifier, turn_ntfy_subscriber_if_t* subscriber)
{
	if(notifier && subscriber) {
	  notifier->subscribers = (turn_ntfy_subscriber_if_t**)turn_realloc(notifier->subscribers,0,(sizeof(turn_ntfy_subscriber_if_t*)*(notifier->subscriber_count+1)));
	  notifier->subscribers[notifier->subscriber_count] = subscriber;
	  notifier->subscriber_count += 1;
	}
}

static void subscribers_init(turn_notifier_t *notifier){
    
    size_t i;
    
    for(i=0; i<(notifier->subscriber_count); i++){
        if(notifier->subscribers[i]->init) {
            notifier->subscribers[i]->long_term_data = notifier->subscribers[i]->init();
        }
    }
}

static void subscribers_notify(turn_notifier_t *notifier, TURN_NTFY_LEVEL level, const s08bits* string){
    
    size_t i;
    
    for(i=0; i<(notifier->subscriber_count); i++){
        if(notifier->subscribers[i]->notify) {
            notifier->subscribers[i]->notify(notifier->subscribers[i]->long_term_data, level, string);
        }
    }
}

static void subscribers_remove(turn_notifier_t *notifier){
    
    size_t i;
    
    for(i=0; i<(notifier->subscriber_count); i++){
        if(notifier->subscribers[i]->remove) {
            notifier->subscribers[i]->remove(notifier->subscribers[i]->long_term_data);
        }
    }
}

static turn_notifier_t* notifier_interface_get(void){
    
    (void) pthread_once(&notifier_key_once, make_notifier_key);
    
    turn_notifier_t *notifier = (turn_notifier_t *)pthread_getspecific(notifier_key);
    
    if(!notifier){
        
        turn_notifier_t* notifier=(turn_notifier_t*)turn_malloc(sizeof(turn_notifier_t));
        if(!notifier) return notifier;
        
        ns_bzero(notifier,sizeof(turn_notifier_t));

        subscriber_add(notifier,udp_subscriber_inferface_get());
      
        subscribers_init(notifier);

        pthread_setspecific(notifier_key, notifier);
    }
    return notifier;
}

static void notifier_interface_remove(void*notifier_p){
    
    turn_notifier_t *notifier = (turn_notifier_t *)notifier_p;
    
    if(notifier){

        subscribers_remove(notifier);

        turn_free(notifier,sizeof(turn_notifier_t));
    }
}

int turn_ntfy_check(){
    
    turn_notifier_t* notifier = notifier_interface_get();

    if(notifier){
        if(notifier->subscriber_count>0)
            return 1;
    } 
    return 0;
}

void turn_ntfy_func_default(TURN_NTFY_LEVEL level, const s08bits* format, ...){
    
#define MAX_RTPPRINTF_BUFFER_SIZE (1024)
	char string[MAX_RTPPRINTF_BUFFER_SIZE+1];
#undef MAX_RTPPRINTF_BUFFER_SIZE

        va_list args;
        
        turn_notifier_t* notifier = notifier_interface_get();
        
        if(notifier){
            va_start(args,format);

            vsnprintf(string, sizeof(string)-1, format, args);
            string[sizeof(string)-1]=0;

            va_end(args);
            
            subscribers_notify(notifier, level, string);
        }
}