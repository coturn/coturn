#ifndef __DBD_REST__
#define __DBD_REST__

#include "dbdriver.h"

#if !defined(TURN_NO_REST)
#include <curl/curl.h>
#include <json.h>

#define REST_METHOD_GET 1
#define REST_METHOD_POST 2
#define REST_METHOD_PUT 3
#define REST_METHOD_DELETE 4
#define REST_CONTENT_TYPE_APPLICATION_JSON 5
#define REST_CONTENT_TYPE_TEXT_XML 6 
#define REST_CONTENT_TYPE_X_WWW_FORM_URLENCODED 7

#define REST_CONTENT_TYPE_APPLICATION_JSON_STRING "json"
#define REST_CONTENT_TYPE_TEXT_XML_STRING "xml" 
#define REST_CONTENT_TYPE_X_WWW_FORM_URLENCODED_STRING "urlencoded"

#define REST_CLIENT_FIELD_ALG "as_rs_alg"
#define REST_CLIENT_FIELD_REALM "realm"
#define REST_CLIENT_FIELD_KEY "ikm_key"
#define REST_CLIENT_FIELD_TIMESTAMP "timestamp" 
#define REST_CLIENT_FIELD_LIFETIME "lifetime"

#define REST_CLIENT_FIELD_USERNAME "username"
#define REST_CLIENT_FIELD_SECRET "secret"

#define HTTP_MAX_URL_SIZE 512
#define HTTP_CONNECTOR_AGENT "coturn-rest-connector/1.0"
#define HTTP_CONTENT_TYPE "Content-Type: application/json"
#define HTTP_TIMEOUT 2
#define HTTP_RESPONSE_MAX_BUFFER 10240 
#define HTTP_RESPONSE_BUFFER 1350 // MTU without headers overhead

#define HTTP_METHOD_DELETE "DELETE"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rest_response_buffer {
    long code;
    char *reason;
    char *payload;
    size_t size;
} rest_response_buffer_t;

typedef struct rest_client_instance {
    char url[512];
    CURL *instance;
    struct curl_slist *sl;
} rest_client_instance_t;

void rest_client_global_init(void);
void rest_client_global_shutdown(void);
rest_client_instance_t *rest_client_instance_init(char *url);
int rest_client_make_query(rest_client_instance_t *instance, rest_response_buffer_t *container,int method, void *body);
void rest_client_instance_free(rest_client_instance_t *instance);
void rest_client_response_free(rest_response_buffer_t *response_buffer);

// rest_client_instance_t *get_rest_connection(void);
const turn_dbdriver_t *get_rest_dbdriver(void);

// For test purpose only
int parse_json_response(char *payload, oauth_key_data_raw *key);

int REST_CONTENT_TYPE;

#ifdef __cplusplus
}
#endif

#endif
/// __DBD_REST__///
#endif
