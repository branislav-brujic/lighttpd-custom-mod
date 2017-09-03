#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"
#include "response.h"
#include "inet_ntop_cache.h"

#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>


/* CHECK IP */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
/* CHECK IP END */

#if defined(HAVE_PCRE_H)
#include <pcre.h>
#endif

typedef struct {
    buffer *server_ip;
    buffer *server_port;
    buffer *download_url;
    buffer *deny_url;
    unsigned short debug;

#if defined(HAVE_PCRE_H)
    pcre *download_regex;
#endif

} plugin_config;

typedef struct {
    PLUGIN_DATA;
    buffer *tmp_buf;
    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;



// server address, port, data

int send_to_server(const char *server_ip, char *server_port, const char *client_ip) {

    struct sockaddr_in servaddr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int result;

    memset(&servaddr, 0, sizeof (servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(atoi(server_port));
    servaddr.sin_addr.s_addr = inet_addr(server_ip);

    connect(sock, (struct sockaddr *) &servaddr, sizeof (servaddr));
    send(sock, client_ip, strlen(client_ip), 0);
    int bufsize = 2048; /* a 2K buffer */
    void *message = malloc(bufsize);
    recv(sock, message, bufsize, 0);
    close(sock);
    result = strtoul(message, NULL, 0);
    free(message);
    return result;

}

/* init the plugin data */
INIT_FUNC(mod_protect_download_init) {
    plugin_data *p;
    p = calloc(1, sizeof (*p));
    p->tmp_buf = buffer_init();
    return p;
}

/* destroy the plugin data */
FREE_FUNC(mod_protect_download_free) {
    plugin_data *p = p_d;
    UNUSED(srv);
    if (!p) return HANDLER_GO_ON;
    if (p->config_storage) {
        size_t i;
        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];

            if (!s) continue;
            buffer_free(s->server_ip);
            buffer_free(s->server_port);
            buffer_free(s->download_url);
            buffer_free(s->deny_url);

#if defined(HAVE_PCRE_H)
            if (s->download_regex) pcre_free(s->download_regex);
#endif

            free(s);
        }
        free(p->config_storage);
    }

    buffer_free(p->tmp_buf);

    free(p);

    return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_protect_download_set_defaults) {
    plugin_data *p = p_d;
    size_t i = 0;


    config_values_t cv[] = {
        { "protect-download.server-ip", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION}, /* 0 */
        { "protect-download.server-port", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION}, /* 1 */
        { "protect-download.download-url", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION}, /* 2 */
        { "protect-download.deny-url", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION}, /* 3 */
        { "protect-download.debug", NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION}, /* 4 */
        { NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET}
    };

    if (!p) return HANDLER_ERROR;

    p->config_storage = calloc(1, srv->config_context->used * sizeof (specific_config *));

    for (i = 0; i < srv->config_context->used; i++) {
        plugin_config *s;
#if defined(HAVE_PCRE_H)
        const char *errptr;
        int erroff;
#endif


        s = calloc(1, sizeof (plugin_config));
        s->server_ip = buffer_init();
        s->server_port = buffer_init();
        s->download_url = buffer_init();
        s->deny_url = buffer_init();

        cv[0].destination = s->server_ip;
        cv[1].destination = s->server_port;
        cv[2].destination = s->download_url;
        cv[3].destination = s->deny_url;
        cv[4].destination = &(s->debug);

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, ((data_config *) srv->config_context->data[i])->value, cv)) {
            return HANDLER_ERROR;
        }

#if defined(HAVE_PCRE_H)
        if (!buffer_is_empty(s->download_url)) {
            if (NULL == (s->download_regex = pcre_compile(s->download_url->ptr,
                    0, &errptr, &erroff, NULL))) {

                log_error_write(srv, __FILE__, __LINE__, "sbss",
                        "compiling regex for download-url failed:",
                        s->download_url, "pos:", erroff);
                return HANDLER_ERROR;
            }
        }

#else
        log_error_write(srv, __FILE__, __LINE__, "s",
                "PCRE are require, but were not found, aborting");
        return HANDLER_ERROR;
#endif

    }

    return HANDLER_GO_ON;
}
#define PATCH(x) \
	p->conf.x = s->x;

static int mod_protect_download_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

#if defined(HAVE_PCRE_H)
    PATCH(download_regex);
#endif
    PATCH(server_ip);
    PATCH(server_port);
    PATCH(download_url);
    PATCH(deny_url);
    PATCH(debug);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *) srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("protect-download.server-ip"))) {
                PATCH(server_ip);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("protect-download.server-port"))) {
                PATCH(server_port);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("protect-download.download-url"))) {
#if defined(HAVE_PCRE_H)
                PATCH(download_regex);
#endif
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("protect-download.deny-url"))) {
                PATCH(deny_url);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("protect-download.debug"))) {
                PATCH(debug);
            }
        }
    }

    return 0;
}
#undef PATCH

URIHANDLER_FUNC(mod_protect_download_uri_handler) {
    plugin_data *p = p_d;
    const char *remote_ip;
    data_string *ds;

#if defined(HAVE_PCRE_H)
    int n;
#define N 10
    int ovec[N * 3];

    if (con->mode != DIRECT) return HANDLER_GO_ON;

    if (con->uri.path->used == 0) return HANDLER_GO_ON;

    mod_protect_download_patch_connection(srv, con, p);

    if (!p->conf.download_regex) return HANDLER_GO_ON;


    /* check is ip behind proxy */
    if (NULL != (ds = (data_string *) array_get_element(con->request.headers, "X-Forwarded-For"))) {
        /* X-Forwarded-For contains the ip behind the proxy */
        remote_ip = ds->value->ptr;
    } else {
        /* ip si not behind proxy */
        remote_ip = inet_ntop_cache_get_ip(srv, &(con->dst_addr));
    }

    /* check if URL is a download -> check IP in DB, update timestamp */
    if ((n = pcre_exec(p->conf.download_regex, NULL, con->uri.path->ptr, con->uri.path->used - 1, 0, 0, ovec, 3 * N)) < 0) {

        if (n != PCRE_ERROR_NOMATCH) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                    "execution error while matching: ", n);
            return HANDLER_ERROR;
        }
        if (p->conf.debug) {
            log_error_write(srv, __FILE__, __LINE__, "s", "(debug) No door to get out.");
        }
        return HANDLER_GO_ON;

    } else {
        /* the download uri matched */
        int res = send_to_server(p->conf.server_ip->ptr, p->conf.server_port->ptr, remote_ip);
        if (1 != res) {
            /* not found back to deny url*/
            response_header_insert(srv, con, CONST_STR_LEN("Location"), CONST_BUF_LEN(p->conf.deny_url));
            /* http response code*/
            con->http_status = 307;
            con->mode = DIRECT;
            con->file_finished = 1;
            //if (p->conf.debug) {
            //    log_error_write(srv, __FILE__, __LINE__, "sdsd", "(debug) checking IP:", remote_ip, ' ', res);
            //}
            return HANDLER_FINISHED;
        }
        UNUSED(res);

    }

#else
    UNUSED(srv);
    UNUSED(con);
    UNUSED(p_d);
#endif

    return HANDLER_GO_ON;
}



/* this function is called at dlopen() time and inits the callbacks */

int mod_protect_download_plugin_init(plugin *p);

int mod_protect_download_plugin_init(plugin *p) {
    p->version = LIGHTTPD_VERSION_ID;
    p->name = buffer_init_string("protect_download");

    p->init = mod_protect_download_init;
    p->handle_uri_clean = mod_protect_download_uri_handler;
    p->set_defaults = mod_protect_download_set_defaults;
    p->cleanup = mod_protect_download_free;

    p->data = NULL;

    return 0;
}