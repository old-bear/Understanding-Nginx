extern "C" {
#include <ngx_core.h>
#include <ngx_http.h>
}

typedef struct {
    ngx_str_t     my_str;
    ngx_int_t     my_num;
    ngx_flag_t    my_flag;
    size_t        my_size;
    ngx_array_t*  my_str_array;
    ngx_array_t*  my_keyval;
    off_t         my_off;
    ngx_msec_t    my_msec;
    time_t        my_sec;
    ngx_bufs_t    my_bufs;
    ngx_uint_t    my_enum_seq;
    ngx_uint_t    my_bitmask;
    ngx_uint_t    my_access;
    ngx_path_t*   my_path;

    ngx_str_t     my_config_str;
    ngx_int_t     my_config_num;

    ngx_http_upstream_conf_t upstream;
} ngx_http_mytest_conf_t;

typedef struct {
    ngx_http_status_t status;

    ngx_str_t stock[9];
} ngx_http_mytest_ctx_t;

static ngx_conf_enum_t test_enums[] = {
    { ngx_string("apple"), 1},
    { ngx_string("banana"), 2},
    { ngx_string("orange"), 3},
    { ngx_null_string, 0}
};

static ngx_conf_bitmask_t test_bitmasks[] = {
    { ngx_string("good"), 0x0002},
    { ngx_string("better"), 0x0004},
    { ngx_string("best"), 0x0008},
    { ngx_null_string, 0},
};

// Copy from ngx_http_proxy_module.c since it's static
static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

static void* ngx_http_mytest_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_mytest_conf_t* mycf;

    mycf = (ngx_http_mytest_conf_t*)
            ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_conf_t));
    if (mycf == NULL) {
        return NULL;
    }

    mycf->my_flag = NGX_CONF_UNSET;
    mycf->my_num = NGX_CONF_UNSET;
    mycf->my_str_array = (ngx_array_t*)NGX_CONF_UNSET_PTR;
    mycf->my_keyval = NULL;
    mycf->my_off = NGX_CONF_UNSET;
    mycf->my_msec = NGX_CONF_UNSET;
    mycf->my_sec = NGX_CONF_UNSET;
    mycf->my_size = NGX_CONF_UNSET;
    mycf->my_access = NGX_CONF_UNSET_UINT;

    mycf->upstream.connect_timeout = NGX_CONF_UNSET_UINT;
    mycf->upstream.send_timeout = 60000;
    mycf->upstream.read_timeout = 60000;
    mycf->upstream.store_access = 0600;
    mycf->upstream.buffering = 0;
    mycf->upstream.bufs.num = 8;
    mycf->upstream.bufs.size = ngx_pagesize;
    mycf->upstream.buffer_size = ngx_pagesize;
    mycf->upstream.busy_buffers_size = 2 * ngx_pagesize;
    mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;
    mycf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    mycf->upstream.hide_headers = (ngx_array_t*)NGX_CONF_UNSET_PTR;
    mycf->upstream.pass_headers = (ngx_array_t*)NGX_CONF_UNSET_PTR;
    
    return mycf;
}

static char*
ngx_http_mytest_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child) {
    ngx_http_mytest_conf_t* prev = (ngx_http_mytest_conf_t*)parent;
    ngx_http_mytest_conf_t* conf = (ngx_http_mytest_conf_t*)child;

    // Use prev iff conf is NULL
    ngx_conf_merge_str_value(conf->my_str, prev->my_str, "defaultstr");
    ngx_conf_merge_uint_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(
            cf, &conf->upstream, &prev->upstream,
            ngx_http_proxy_hide_headers, &hash) != NGX_OK) {
        return (char*)NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char*
ngx_conf_set_myconfig(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_mytest_conf_t* mycf = (ngx_http_mytest_conf_t*)conf;

    // cf->args is a ngx_array_t whose element is ngx_str_t
    // It stores all the arguments starting from index 1
    ngx_str_t* value = (ngx_str_t*)cf->args->elts;
    if (cf->args->nelts > 1) {
        mycf->my_config_str = value[1];
    }
    if (cf->args->nelts > 2) {
        mycf->my_config_num = ngx_atoi(value[2].data, value[2].len);
        if (mycf->my_config_num == NGX_ERROR) {
            return "invalid number";
        }
    }

    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_mytest_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_mytest_create_loc_conf,
    ngx_http_mytest_merge_loc_conf
};

static char*
ngx_http_mytest(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

static ngx_command_t ngx_http_mytest_commands[] = {
    { ngx_string("mytest"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
      ngx_http_mytest,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("test_flag"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_flag),
      NULL },

    { ngx_string("test_str"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_str),
      NULL },

    { ngx_string("test_str_array"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_str_array),
      NULL },

    { ngx_string("test_keyval"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_keyval),
      NULL },

    { ngx_string("test_num"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_num),
      NULL },

    { ngx_string("test_size"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_size),
      NULL },

    { ngx_string("test_off"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_off),
      NULL },

    { ngx_string("test_msec"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_msec),
      NULL },

    { ngx_string("test_sec"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_sec),
      NULL },

    { ngx_string("test_bufs"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_bufs),
      NULL },

    { ngx_string("test_enum"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_enum_seq),
      test_enums },

    { ngx_string("test_bitmask"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_bitmask),
      test_bitmasks },

    { ngx_string("test_access"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_access),
      NULL },

    { ngx_string("test_path"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, my_path),
      test_bitmasks },
    
    { ngx_string("test_myconfig"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
      ngx_conf_set_myconfig,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("upstream_connect_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mytest_conf_t, upstream.connect_timeout),
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_mytest_module = {
    NGX_MODULE_V1,
    &ngx_http_mytest_module_ctx,
    ngx_http_mytest_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_mytest_handler_hello_world(ngx_http_request_t* r) {
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // Discard request body 
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_t type = ngx_string("text/plain");
    ngx_str_t response = ngx_string("Hello World!");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = response.len;

    // Send response header
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    // Construct ngx_buf_t to hold response body
    ngx_buf_t* b;
    b = ngx_create_temp_buf(r->pool, response.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, response.data, response.len);
    b->last = b->pos + response.len;
    // Mark this buf as the last one
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
    
    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
mytest_upstream_create_request(ngx_http_request_t* r) {
    static ngx_str_t backend_query_line = ngx_string(
        "GET /s?wd=%V HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");

    // -2 for format characters %V
    ngx_int_t query_len = backend_query_line.len + r->args.len - 2;
    ngx_buf_t* b = ngx_create_temp_buf(r->pool, query_len);
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->last = b->pos + query_len;

    ngx_snprintf(b->pos, query_len, (char*)backend_query_line.data, &r->args);
    // Set request body into `request_bufs', which is a ngx_chain_t
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL) {
        return NGX_ERROR;
    }
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    r->header_hash = 1;  // MUST NOT be 0
    return NGX_OK;
}

static ngx_int_t
mytest_upstream_process_header(ngx_http_request_t* r) {
    ngx_int_t rc;
    ngx_http_upstream_main_conf_t* umcf = (ngx_http_upstream_main_conf_t*)
            ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    
    for ( ;; ) {
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        // NGX_OK means one header has been parsed successfully
        if (rc == NGX_OK) {
            // Append the parsed header into headers_in
            ngx_table_elt_t* h = (ngx_table_elt_t*)
                    ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            // +1 for '\0'
            h->key.data = (u_char*)ngx_pnalloc(
                r->pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }
            // Copy key and value
            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;
            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            // Some headers have special operation
            ngx_http_upstream_header_t* hh = (ngx_http_upstream_header_t*)
                    ngx_hash_find(&umcf->headers_in_hash, h->hash,
                                  h->lowcase_key, h->key.len);
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }
            
            continue;
        }

        // NGX_HTTP_PARSE_HEADER_DONE means the completion of header part
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            // Add `server' and `date' header iff not exist
            if (r->upstream->headers_in.server == NULL) {
                ngx_table_elt_t* h = (ngx_table_elt_t*)
                        ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*)"server";
            }

            if (r->upstream->headers_in.date == NULL) {
                ngx_table_elt_t* h = (ngx_table_elt_t*)
                        ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');
                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*)"date";
            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        // Regard other return values as error
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static ngx_int_t
mytest_process_status_line(ngx_http_request_t* r) {
    ngx_http_mytest_ctx_t* ctx = (ngx_http_mytest_ctx_t*)
            ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_upstream_t* u = r->upstream;
    ngx_int_t rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    if (rc == NGX_AGAIN) {
        return rc;
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to parse HTTP header from upstream");
        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        return NGX_OK;
    }

    // Fill status line into headers_in so that it can be passed back to client
    if (u->state) {
        u->state->status = ctx->status.code;
    }
    u->headers_in.status_n = ctx->status.code;

    size_t len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;
    u->headers_in.status_line.data = (u_char*)ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    // Leave the rest to process_headers
    u->process_header = mytest_upstream_process_header;
    return mytest_upstream_process_header(r);
}

static void
mytest_upstream_finalize_request(ngx_http_request_t* r, ngx_int_t rc) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "mytest_upstream_finalize_request");
}

static ngx_int_t ngx_http_mytest_handler_upstream(ngx_http_request_t* r) {
    ngx_http_mytest_ctx_t* myctx = (ngx_http_mytest_ctx_t*)
            ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (myctx == NULL) {
        myctx = (ngx_http_mytest_ctx_t*)
                ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
        if (myctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
    }

    // Create an upstream request
    if (ngx_http_upstream_create(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    ngx_http_mytest_conf_t* mycf = (ngx_http_mytest_conf_t*)
            ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
    ngx_http_upstream_t* u = r->upstream;
    // Use global conf for ngx_http_upstream_conf_t
    u->conf = &mycf->upstream;
    u->buffering = mycf->upstream.buffering;

    // Set the upstream address
    u->resolved = (ngx_http_upstream_resolved_t*)
            ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ngx_palloc resolved error. %s.", strerror(errno));
        return NGX_ERROR;
    }

    static struct sockaddr_in backend_addr;
    struct hostent* phost = gethostbyname("www.baidu.com");
    if (phost == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "gethostbyname fail. %s.", strerror(errno));
        return NGX_ERROR;
    }
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(80);
    ngx_memcpy(&backend_addr.sin_addr, phost->h_addr, phost->h_length);
                  
    u->resolved->sockaddr = (struct sockaddr*)&backend_addr;
    u->resolved->socklen = sizeof(backend_addr);
    u->resolved->port = htons(80);
    u->resolved->naddrs = 1;

    // Set the callback for upstream
    u->create_request = mytest_upstream_create_request;
    u->process_header = mytest_process_status_line;
    u->finalize_request = mytest_upstream_finalize_request;

    // Add ref count before upstream to prevent main context being recycled
    r->main->count++;
    // Start upstream request
    ngx_http_upstream_init(r);
    // Return NGX_DONE to stand for asynchronous job done
    return NGX_DONE;
}

static void mytest_post_handler(ngx_http_request_t* r) {
    if (r->headers_out.status != NGX_HTTP_OK) {
        ngx_http_finalize_request(r, r->headers_out.status);
        return;
    }

    ngx_http_mytest_ctx_t* myctx = (ngx_http_mytest_ctx_t*)
            ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    ngx_str_t output_format =
            ngx_string("stock[%V], Today current price: %V, volumn: %V");
    int body_len = output_format.len + myctx->stock[0].len
            + myctx->stock[1].len + myctx->stock[8].len - 6;
    r->headers_out.content_length_n = body_len;

    // Allocate memory to hold response body
    ngx_buf_t* b = ngx_create_temp_buf(r->pool, body_len);
    ngx_snprintf(b->pos, body_len, (char*)output_format.data,
                 &myctx->stock[0], &myctx->stock[1], &myctx->stock[8]);
    b->last = b->pos + body_len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    static ngx_str_t type = ngx_string("text/plain; charset=GBK");
    r->headers_out.content_type = type;
    r->headers_out.status = NGX_HTTP_OK;

    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r, &out);

    // Explicit call to finalize since nginx won't do this now
    ngx_http_finalize_request(r, ret);
}

static ngx_int_t mytest_subrequset_post_handler(
    ngx_http_request_t* r, void* data, ngx_int_t rc) {
    ngx_http_request_t* pr = r->parent;
    // Notice that parameter `data' also points to context
    // However, We use another approach to show that request
    // context is still inside parent request
    ngx_http_mytest_ctx_t* myctx = (ngx_http_mytest_ctx_t*)
            ngx_http_get_module_ctx(pr, ngx_http_mytest_module);
    pr->headers_out.status = r->headers_out.status;
    if (r->headers_out.status == NGX_HTTP_OK) {
        int count = 0;
        // The default input_filter will fill upstream response into `buffer'
        ngx_buf_t* p_recv_buf = &r->upstream->buffer;
        for (; p_recv_buf->pos != p_recv_buf->last; p_recv_buf->pos++) {
            // Sample response:
            // var hq_str_sh600710="ST常林,6.910,6.910,6.850,6.910,6.840,6.850,..."
            if (*p_recv_buf->pos == ',' || *p_recv_buf->pos == '\"') {
                if (count > 0) {
                    myctx->stock[count-1].len =
                            p_recv_buf->pos - myctx->stock[count-1].data;
                }
                count++;
                myctx->stock[count-1].data = p_recv_buf->pos + 1;
            }
            if (count > 9) {
                break;
            }
        }
    }
    // Set the callback when parent request is going to send back response
    pr->write_event_handler = mytest_post_handler;
    return NGX_OK;
}

static ngx_int_t ngx_http_mytest_handler_stock(ngx_http_request_t* r) {
    ngx_http_mytest_ctx_t* myctx = (ngx_http_mytest_ctx_t*)
            ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (myctx == NULL) {
        myctx = (ngx_http_mytest_ctx_t*)
                ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
        if (myctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
    }

    // Set the callback when subrequest returns
    ngx_http_post_subrequest_t* psr = (ngx_http_post_subrequest_t*)
            ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }
    psr->handler = mytest_subrequset_post_handler;
    psr->data = myctx;

    // Construct subrequest, redirect to /stock and use the original args
    static ngx_str_t sub_uri = ngx_string("/stock");
    // Issue subrequest
    // Set NGX_HTTP_SUBREQUEST_IN_MEMORY to put upstream response in buffer    
    ngx_http_request_t* sr;
    ngx_int_t rc = ngx_http_subrequest(r, &sub_uri, &r->args, &sr, psr,
                                       NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    // Return NGX_DONE to yield
    return NGX_DONE;
}

static char*
ngx_http_mytest(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_core_loc_conf_t* clcf;

    // Get the conf structure of mytest (include http/server block)
    clcf = (ngx_http_core_loc_conf_t*)
            ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    // Set the callback when matching this conf
    clcf->handler = ngx_http_mytest_handler_stock;

    return NGX_CONF_OK;
}

