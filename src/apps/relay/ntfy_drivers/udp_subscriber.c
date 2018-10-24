#include "udp_subscriber.h"
#include "ns_turn_utils.h"
#include "apps/relay/mainrelay.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>

typedef struct _udp_subs_ltd{
    char config_string[1025];
    char* host;
    unsigned int port;
    int sockfd;
    struct sockaddr_in server_addr; 
    struct hostent *hostent;
}udp_subs_ltd_t;

subs_long_term_data_t udp_init(void);
int udp_notify( subs_long_term_data_t long_term_data, TURN_NTFY_LEVEL level , const s08bits* message );
int udp_remove( subs_long_term_data_t long_term_data);

int udp_subscriber_flag(){
    return turn_params.udp_notifier;
}

static char* udp_subs_config_str( void ){
    return turn_params.udp_notifier_params;
}

static int udp_subs_config_parse( udp_subs_ltd_t* data ){
    	
    int ret = 0;
    char *s0=turn_strdup(data->config_string);
    char *s = s0;

    while(s && *s) {

            while(*s && (*s==' ')) ++s;
            char *snext = strstr(s," ");
            if(snext) {
                    *snext = 0;
                    ++snext;
            }

            char* seq = strstr(s,"=");
            if(!seq) {
                ret = -1;
                break;                        
            }

            *seq = 0;
            if(!strcmp(s,"host"))
                    data->host = turn_strdup(seq+1);
            else if(!strcmp(s,"ip"))
                    data->host = turn_strdup(seq+1);
            else if(!strcmp(s,"addr"))
                    data->host = turn_strdup(seq+1);
            else if(!strcmp(s,"ipaddr"))
                    data->host = turn_strdup(seq+1);
            else if(!strcmp(s,"hostaddr"))
                    data->host = turn_strdup(seq+1);
            else if(!strcmp(s,"port"))
                    data->port = (unsigned int)atoi(seq+1);
            else if(!strcmp(s,"p"))
                    data->port = (unsigned int)atoi(seq+1);
            else {
                ret = -1;
                break;     
            }

            s = snext;
    }

    turn_free(s0, strlen(s0)+1);
    
    if ( ret == 0 ){
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"UDP notifier parameters: host=%s port=%d\n",data->host,data->port);
    }else{
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"WRONG UDP notifier parameters: %s\n",data->config_string);
    }
    
    return ret;
}

subs_long_term_data_t udp_init( void ){
        
    udp_subs_ltd_t* data=(udp_subs_ltd_t*)turn_malloc(sizeof(udp_subs_ltd_t));
        if(!data) return data;

    ns_bzero(data,sizeof(udp_subs_ltd_t));
        
    STRCPY(data->config_string, udp_subs_config_str());
    
    if( udp_subs_config_parse(data) < 0 ){
        return NULL;
    }
    
    data->hostent = gethostbyname(data->host);
    if ( data->hostent == NULL) { 
        return NULL;
    }
    
    data->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (data->sockfd == -1) {
        return NULL;
    }

    data->server_addr.sin_family = AF_INET;
    data->server_addr.sin_port = htons(data->port);
    data->server_addr.sin_addr = *((struct in_addr *)data->hostent->h_addr);
    bzero(&(data->server_addr.sin_zero), 8);
    
    return (subs_long_term_data_t)data;
}

int udp_notify( subs_long_term_data_t long_term_data, TURN_NTFY_LEVEL level , const s08bits* message ){
    
    UNUSED_ARG(level);
    
    udp_subs_ltd_t* data = (udp_subs_ltd_t*)long_term_data;
    
    if(!data)
        return -1;
      
    return (int) sendto(data->sockfd, message, strlen(message), 0,(struct sockaddr *)&data->server_addr, sizeof(struct sockaddr));
}

int udp_remove( subs_long_term_data_t long_term_data){
    
    udp_subs_ltd_t* data = (udp_subs_ltd_t*)long_term_data;
    
    close(data->sockfd);
    
    turn_free(data->host,strlen(data->host));
    turn_free(data->hostent,sizeof(struct hostent));
    turn_free(data,sizeof(udp_subs_ltd_t));
    
    return 0;
}

static turn_ntfy_subscriber_if_t subscriber = {
    .name="udp",
    .init=udp_init,
    .notify=udp_notify,
    .remove=udp_remove
};

turn_ntfy_subscriber_if_t* udp_subscriber_inferface_get(){
    
    if(udp_subscriber_flag())
        return &subscriber;
    return (turn_ntfy_subscriber_if_t*)NULL;
}