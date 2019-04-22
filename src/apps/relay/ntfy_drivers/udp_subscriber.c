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
    ioa_addr addr;
}udp_subs_ltd_t;

subs_long_term_data_t udp_init(void);
int udp_notify( subs_long_term_data_t long_term_data, TURN_NTFY_LEVEL level , const char* message );
int udp_remove( subs_long_term_data_t long_term_data);

int udp_subscriber_flag(){
    return turn_params.udp_notifier;
}

static char* udp_subs_config_str( void ){
    return turn_params.udp_notifier_params;
}

static int udp_subs_config_parse( udp_subs_ltd_t* data ){
    	
    int ret = 0;
    char *s0=strdup(data->config_string);
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
                    data->host = strdup(seq+1);
            else if(!strcmp(s,"ip"))
                    data->host = strdup(seq+1);
            else if(!strcmp(s,"addr"))
                    data->host = strdup(seq+1);
            else if(!strcmp(s,"ipaddr"))
                    data->host = strdup(seq+1);
            else if(!strcmp(s,"hostaddr"))
                    data->host = strdup(seq+1);
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

    free(s0);
    
    if ( ret == 0 ){
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"UDP notifier parameters: host=%s port=%d\n",data->host,data->port);
    }else{
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"WRONG UDP notifier parameters: %s\n",data->config_string);
    }
    
    return ret;
}

subs_long_term_data_t udp_init( void ){
        
    udp_subs_ltd_t* data=(udp_subs_ltd_t*)malloc(sizeof(udp_subs_ltd_t));
        if(!data) return data;

    bzero(data,sizeof(udp_subs_ltd_t));
        
    STRCPY(data->config_string, udp_subs_config_str());
    
    if( udp_subs_config_parse(data) < 0 ){
        return NULL;
    }
    
    if(make_ioa_addr((const uint8_t*)data->host,0,&(data->addr))<0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot set address %s\n",data->host);
        return NULL;
    }

    addr_set_port(&(data->addr),data->port);
    
    data->sockfd = socket(data->addr.ss.sa_family, SOCK_DGRAM, 0);
    if (data->sockfd < 0) {
        perror("socket");
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot open socket\n");
        return NULL;
    }
    
    return (subs_long_term_data_t)data;
}

int udp_notify( subs_long_term_data_t long_term_data, TURN_NTFY_LEVEL level , const char* message ){
    
    UNUSED_ARG(level);
    
    udp_subs_ltd_t* data = (udp_subs_ltd_t*)long_term_data;
    int slen=0;
    
    if(!data)
        return -1;
    
    slen = get_ioa_addr_len((const ioa_addr*)&(data->addr));
      
    return (int) sendto(data->sockfd, message, strlen(message), 0,(const struct sockaddr*)&(data->addr), (socklen_t) slen);
}

int udp_remove( subs_long_term_data_t long_term_data){
    
    udp_subs_ltd_t* data = (udp_subs_ltd_t*)long_term_data;
    
    close(data->sockfd);
    
    free(data->host);
    free(data);
    
    return 0;
}

static turn_ntfy_subscriber_if_t subscriber = {
    /*name*/    "udp",
    /*date*/    NULL,
    /*init*/    udp_init,
    /*notify*/  udp_notify,
    /*remove*/  udp_remove
};

turn_ntfy_subscriber_if_t* udp_subscriber_inferface_get(){
    
    if(udp_subscriber_flag())
        return &subscriber;
    return (turn_ntfy_subscriber_if_t*)NULL;
}