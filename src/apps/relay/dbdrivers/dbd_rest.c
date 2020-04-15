#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../mainrelay.h"
#include "dbd_rest.h"

#if !defined(TURN_NO_REST)

// must be static
static rest_client_instance_t *get_rest_connection(void) {

	persistent_users_db_t *connection_link = get_persistent_users_db();
	// check pthred_specific
	// if nothing - prepare new one;

	TURN_LOG_FUNC(TURN_LOG_LEVEL_CONTROL, "Getting connection details\n", NULL);
	rest_client_instance_t *rest = (rest_client_instance_t *)pthread_getspecific(connection_key);

	if (!rest) {
		rest = calloc(1,sizeof(rest_client_instance_t));

		TURN_LOG_FUNC(TURN_LOG_LEVEL_CONTROL, "No connection details found, inititaing new one...\n", NULL);
		rest = rest_client_instance_init((char *)connection_link);
		if (!rest->instance) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Сan't init http client\n", NULL);
			return NULL;
		}
		(void) pthread_setspecific(connection_key, rest);

	}
	return rest;
}

static size_t rest_client_response_recieve(void *contents, size_t size, size_t nmemb, void *response_buffer) {

	size_t realsize = size * nmemb;
	rest_response_buffer_t *buff = (rest_response_buffer_t *)response_buffer;

	buff->payload = realloc(buff->payload, buff->size + realsize + 1);
	if(buff->payload == NULL) {
		/* out of memory! */
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "not enough memory (realloc returned NULL)\n", NULL);
		return 0;
	}

	memcpy(&(buff->payload[buff->size]), contents, realsize);
	buff->size += realsize;
	buff->payload[buff->size] = 0;

	return realsize;
}

void rest_client_global_init() {
	curl_global_init(CURL_GLOBAL_ALL);
}

void rest_client_global_shutdown() {
	curl_global_cleanup();
}

rest_client_instance_t *rest_client_instance_init(char *url) {

	rest_client_instance_t *inst = calloc(1, sizeof(rest_client_instance_t));

	inst->instance = curl_easy_init();

	if ( !inst->instance ) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Can't init HTTP instanse\n", NULL);
		curl_global_cleanup();
		return NULL;
	}

	strncpy(inst->url,url,strlen(url));

	curl_easy_setopt(inst->instance, CURLOPT_URL, inst->url);
	// curl_easy_setopt(instance, CURLOPT_CONNECT_ONLY, 1L);
	curl_easy_setopt(inst->instance, CURLOPT_WRITEFUNCTION, rest_client_response_recieve);
	curl_easy_setopt(inst->instance, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(inst->instance, CURLOPT_TCP_KEEPIDLE, 120L);
	curl_easy_setopt(inst->instance, CURLOPT_TCP_KEEPINTVL, 60L);
	curl_easy_setopt(inst->instance,CURLOPT_TIMEOUT,HTTP_TIMEOUT);
	curl_easy_setopt(inst->instance, CURLOPT_USERAGENT, HTTP_CONNECTOR_AGENT);

	if (strcmp(turn_params.rest_client_content_type, REST_CONTENT_TYPE_APPLICATION_JSON_STRING) == 0) REST_CONTENT_TYPE = REST_CONTENT_TYPE_APPLICATION_JSON;
	if (strcmp(turn_params.rest_client_content_type, REST_CONTENT_TYPE_TEXT_XML_STRING) == 0) REST_CONTENT_TYPE = REST_CONTENT_TYPE_TEXT_XML;
	if (strcmp(turn_params.rest_client_content_type, REST_CONTENT_TYPE_X_WWW_FORM_URLENCODED_STRING) == 0) REST_CONTENT_TYPE = REST_CONTENT_TYPE_X_WWW_FORM_URLENCODED;

	// default
	if (REST_CONTENT_TYPE == 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "REST client's content-type option undefind. Using default: %s\n", REST_CONTENT_TYPE_APPLICATION_JSON);
		REST_CONTENT_TYPE = REST_CONTENT_TYPE_APPLICATION_JSON;
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "REST client expects content-type: %s\n", turn_params.rest_client_content_type);
	}
	return inst;
}

int rest_client_make_query(rest_client_instance_t *inst, rest_response_buffer_t *container, int method, const void *body ) {
	if (!inst->instance) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "http client instance does not exists\n", NULL);
		return 1;
	}

	CURLcode res;
	char GETurl[HTTP_MAX_URL_SIZE];

	switch (method) {

	case REST_METHOD_GET:

		strcpy(GETurl, inst->url);
		strcat(GETurl, "/");
		strcat(GETurl, body);

		curl_easy_setopt(inst->instance, CURLOPT_URL, GETurl);
		curl_easy_setopt(inst->instance, CURLOPT_WRITEDATA, (void *)container);

		break;

	case REST_METHOD_POST:
		curl_easy_setopt(inst->instance, CURLOPT_POST, 1L);
		curl_easy_setopt(inst->instance, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(inst->instance, CURLOPT_WRITEDATA, (void *)container);
		inst->sl = NULL;
		inst->sl = curl_slist_append(inst->sl, HTTP_CONTENT_TYPE);
		curl_easy_setopt(inst->instance, CURLOPT_HTTPHEADER, inst->sl);

		break;

	case REST_METHOD_DELETE:
		curl_easy_setopt(inst->instance, CURLOPT_CUSTOMREQUEST, HTTP_METHOD_DELETE);
		curl_easy_setopt(inst->instance, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(inst->instance, CURLOPT_WRITEDATA, (void *)container);
		inst->sl = NULL;
		inst->sl = curl_slist_append(inst->sl, HTTP_CONTENT_TYPE);
		curl_easy_setopt(inst->instance, CURLOPT_HTTPHEADER, inst->sl);

		break;

	default:
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "method unknown\n", NULL);
		return 1;
	}

	res = curl_easy_perform(inst->instance);

	if(res != CURLE_OK) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "HTTP Request failed: %s\n", (const char*)curl_easy_strerror(res));
		return 1;
	}
	long resp_code;
	curl_easy_getinfo(inst->instance, CURLINFO_RESPONSE_CODE, &resp_code);
	container->code = resp_code;
	return 0;
}

void rest_client_response_free(rest_response_buffer_t *response_buffer) {
	free(response_buffer->payload);
	free(response_buffer);
	response_buffer = NULL;
}

void rest_client_instance_free(rest_client_instance_t *inst) {
	curl_slist_free_all(inst->sl);
	curl_easy_cleanup(inst->instance);
	free(inst);
	inst = NULL;
}

static int parse_json_oauth_key_response(char *payload, oauth_key_data_raw *key) {

	/* reply has to be in the format:
	   {
	   as_rs_alg : "algname",
	   realm: "realm",
	   ikm_key: "ikm_key",
	   timestamp: "timestamp" (not necessary),
	   lifetime: "lifetime" (not necessary)
	   }
	*/

	if (strlen(payload) == 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "No payload\n", NULL);
		return 1;
	}

	int ret = 0;
	json_object *payload_parsed = NULL;
	payload_parsed = json_tokener_parse(payload);

	json_object *alg, *ikm_key, *realm, *timestamp, *lifetime;

	alg = NULL;
	ikm_key = NULL;
	realm = NULL;
	timestamp = NULL;
	lifetime = NULL;

	json_object_object_get_ex(payload_parsed, REST_CLIENT_FIELD_ALG, &alg);
	if (!alg) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "No %s field found at the REST response\n", REST_CLIENT_FIELD_ALG);
		ret = 1;
	}

	json_object_object_get_ex(payload_parsed, REST_CLIENT_FIELD_KEY, &ikm_key);
	if (!ikm_key) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "No %s field found at the REST response\n", REST_CLIENT_FIELD_KEY);
		ret = 1;
	}

	if (ret == 0) {

		json_object_object_get_ex(payload_parsed, REST_CLIENT_FIELD_REALM, &realm);
		json_object_object_get_ex(payload_parsed, REST_CLIENT_FIELD_TIMESTAMP, &timestamp);
		json_object_object_get_ex(payload_parsed, REST_CLIENT_FIELD_LIFETIME, &lifetime);

		strcpy(key->as_rs_alg, json_object_get_string(alg));
		strcpy(key->ikm_key, json_object_get_string(ikm_key));
		strcpy(key->realm, json_object_get_string(realm));
		key->timestamp = json_object_get_int(timestamp);
		key->lifetime = json_object_get_int(lifetime);
	}

	json_object_put(alg);
	json_object_put(ikm_key);
	json_object_put(realm);
	json_object_put(timestamp);
	json_object_put(lifetime);

	return ret;
}

static int rest_get_oauth_key(const uint8_t *kid, oauth_key_data_raw *key) {

	rest_client_instance_t *rest = get_rest_connection();

	if(!rest) {
		return -1;
	}

	rest_response_buffer_t *response_buffer = calloc(1, sizeof(rest_response_buffer_t));
	if (rest_client_make_query(rest, response_buffer, REST_METHOD_GET, (const void *)kid) != 0 ) {
		return -1;
	};

	int  ret = 0;
	if (response_buffer->code != 200) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Got response: %d", response_buffer->code);
		ret = -1;
	}

	if (ret == 0) {
		if (REST_CONTENT_TYPE == REST_CONTENT_TYPE_APPLICATION_JSON) {
			if (parse_json_oauth_key_response(response_buffer->payload, key) != 0) {
				ret = -1;
			}
		}
		else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Not implemented yet\n", NULL);
		}
	}

	rest_client_response_free(response_buffer);
	return ret;
}

static int rest_set_oauth_key(oauth_key_data_raw *key) {
    UNUSED_ARG(key);
	return 0;
}

static int rest_del_oauth_key(const uint8_t *kid) {
    UNUSED_ARG(kid);
	return 0;
}

static int parse_json_secret_response(char *payload, char *secret) {

	/* reply has to be in the format:
	   {
	   username: "username",
	   secret: "secret",
	   }
	*/

	if (strlen(payload) == 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "No payload\n", NULL);
		return 1;
	}

	int ret = 0;
	json_object *payload_parsed = NULL;
	payload_parsed = json_tokener_parse(payload);

	json_object *json_obj_username, *json_obj_secret;

	json_obj_username = NULL;
	json_obj_secret = NULL;

	json_object_object_get_ex(payload_parsed, REST_CLIENT_FIELD_USERNAME, &json_obj_username);
	if (!json_obj_username) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "No %s field found\n", REST_CLIENT_FIELD_USERNAME);
		ret = 1;
	}

	json_object_object_get_ex(payload_parsed, REST_CLIENT_FIELD_SECRET, &json_obj_secret);
	if (!json_obj_secret) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "No %s field found\n", REST_CLIENT_FIELD_SECRET);
		ret = 1;
	}

	if (ret == 0) {

		strcpy(secret, json_object_get_string(json_obj_secret));

	}
	json_object_put(json_obj_username);
	json_object_put(json_obj_secret);

	return ret;
}

// this has to be added to the dbdriver as additional API function. it is new one
static int rest_get_auth_secret(const uint8_t *usname, char *secret) {

	rest_client_instance_t *rest = get_rest_connection();

	if(!rest) {
		return -1;
	}

	rest_response_buffer_t *response_buffer = calloc(1, sizeof(rest_response_buffer_t));

	if (rest_client_make_query(rest,response_buffer, REST_METHOD_GET, (const void *)usname) != 0) {
		return -1;
	}

	int ret = 0;
	if (response_buffer->code != 200) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Got response: %ld\n", response_buffer->code);
		ret = -1;
	}

	if (ret == 0) {
		if (REST_CONTENT_TYPE == REST_CONTENT_TYPE_APPLICATION_JSON) {
			if (parse_json_secret_response(response_buffer->payload, secret) != 0 ) {
				ret = -1;
			}
		}
		else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Not implemented yet\n", NULL);
		}
	}

	return ret;
}


//------- minimal API: -----------//

static const turn_dbdriver_t driver = {
	.set_oauth_key = &rest_set_oauth_key,
	.get_oauth_key = &rest_get_oauth_key,
	.del_oauth_key = &rest_del_oauth_key,
	.get_auth_secret = &rest_get_auth_secret,
};

const turn_dbdriver_t *get_rest_dbdriver(void) {
	return &driver;
}

#else

const turn_dbdriver_t *get_rest_dbdriver(void) {
    return NULL;
}

#endif
