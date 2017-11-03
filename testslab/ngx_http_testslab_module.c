extern "C" {
#include <ngx_core.h>
#include <ngx_http.h>
}

typedef struct {
    u_char rbtree_node_data;   // the last member in rbtree node
    ngx_queue_t queue;         // link all nodes in LRU order
    ngx_msec_t last;           // last access time
    u_short len;               // length of data
    u_char data[1];            // IP+URL
} ngx_http_testslab_node_t;

typedef struct {
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
    ngx_queue_t queue;
} ngx_http_testslab_shm_t;

typedef struct {
    ssize_t shmsize;
    ngx_int_t interval;
    ngx_slab_pool_t* shpool;
    ngx_http_testslab_shm_t* sh;
} ngx_http_testslab_conf_t;

static void
ngx_http_testslab_rbtree_insert_value(ngx_rbtree_node_t* temp,
                                      ngx_rbtree_node_t* node,
                                      ngx_rbtree_node_t* sentinel) {
    ngx_rbtree_node_t** p;
    ngx_http_testslab_node_t* lrn;
    ngx_http_testslab_node_t* lrnt;
    for (;;) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            lrn = (ngx_http_testslab_node_t*)&node->data;
            lrnt = (ngx_http_testslab_node_t*)&temp->data;
            p = ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0
                ? &temp->left : &temp->right;
        }
        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static void
ngx_http_testslab_expire(ngx_http_request_t* r, ngx_http_testslab_conf_t* conf) {
    ngx_time_t* tp = ngx_timeofday();
    ngx_msec_t now = (ngx_msec_t)(tp->sec * 1000 + tp->msec);
    while (1) {
        if (ngx_queue_empty(&conf->sh->queue)) {
            return;
        }
        ngx_queue_t* q = ngx_queue_last(&conf->sh->queue);
        ngx_http_testslab_node_t* lr =
                ngx_queue_data(q, ngx_http_testslab_node_t, queue);
        ngx_rbtree_node_t* node = (ngx_rbtree_node_t*)
                ((u_char*)lr - offsetof(ngx_rbtree_node_t, data));
        ngx_msec_int_t ms = (ngx_msec_int_t)(now - conf->interval);
        if (ms < conf->interval) {
            return;
        }

        ngx_queue_remove(q);
        ngx_rbtree_delete(&conf->sh->rbtree, node);
        // Lock is required outside this function
        ngx_slab_free_locked(conf->shpool, node);
    }
}

static ngx_int_t
ngx_http_testslab_lookup(ngx_http_request_t* r,
                         ngx_http_testslab_conf_t* conf,
                         ngx_uint_t hash, u_char* data, size_t len) {
    ngx_time_t* tp = ngx_timeofday();
    ngx_msec_t now = (ngx_msec_t)(tp->sec * 1000 + tp->msec);

    ngx_rbtree_node_t* node = conf->sh->rbtree.root;
    ngx_rbtree_node_t* sentinel = conf->sh->rbtree.sentinel;

    ngx_http_testslab_node_t* lr;    
    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }

        lr = (ngx_http_testslab_node_t*)&node->data;
        ngx_int_t rc = ngx_memn2cmp(data, lr->data, len, (size_t)lr->len);
        if (rc == 0) {
            ngx_msec_int_t ms = (ngx_msec_int_t)(now - lr->last);
            if (ms > conf->interval) {
                // Grant access since access interval is long enough
                lr->last = now;
                // Move this node to list head
                ngx_queue_remove(&lr->queue);
                ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
                return NGX_DECLINED;
            } else {
                return NGX_HTTP_FORBIDDEN;
            }
        }
        node = rc < 0? node->left : node->right;
    }

    size_t size = offsetof(ngx_rbtree_node_t, data)
            + offsetof(ngx_http_testslab_node_t, data) + len;
    // Expire outdate nodes first
    ngx_http_testslab_expire(r, conf);

    // Lock is required outside this function
    node = (ngx_rbtree_node_t*)ngx_slab_alloc_locked(conf->shpool, size);
    if (node == NULL) {
        return NGX_ERROR;
    }
    node->key = hash;

    lr = (ngx_http_testslab_node_t*)&node->data;
    lr->last = now;
    lr->len = (u_short)len;
    ngx_memcpy(lr->data, data, len);

    ngx_rbtree_insert(&conf->sh->rbtree, node);
    ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
    return NGX_DECLINED;    
}

static void* ngx_http_testslab_create_main_conf(ngx_conf_t* cf) {
    ngx_http_testslab_conf_t* mycf;

    mycf = (ngx_http_testslab_conf_t*)
            ngx_pcalloc(cf->pool, sizeof(ngx_http_testslab_conf_t));
    if (mycf == NULL) {
        return NULL;
    }

    mycf->interval = -1;
    mycf->shmsize = -1;
    return mycf;
}

static ngx_int_t
ngx_http_testslab_shm_init(ngx_shm_zone_t* shm_zone, void* data) {
    ngx_http_testslab_conf_t* conf =
            (ngx_http_testslab_conf_t*)shm_zone->data;
    ngx_http_testslab_conf_t* oconf = (ngx_http_testslab_conf_t*)data;
    if (oconf) {
        // Shared memeory of previous process
        // This may happen when reloading/upgrading
        conf->sh = oconf->sh;
        conf->shpool = oconf->shpool;
        return NGX_OK;
    }

    conf->shpool = (ngx_slab_pool_t*)shm_zone->shm.addr;
    conf->sh = (ngx_http_testslab_shm_t*)
            ngx_slab_alloc(conf->shpool, sizeof(ngx_http_testslab_shm_t));
    if (conf->sh == NULL) {
        return NGX_ERROR;
    }
    conf->shpool->data = conf->sh;

    ngx_queue_init(&conf->sh->queue);

    // Add log context
    size_t len = sizeof(" in testslab \"\"") + shm_zone->shm.name.len;
    conf->shpool->log_ctx = (u_char*)ngx_slab_alloc(conf->shpool, len);
    if (conf->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_sprintf(conf->shpool->log_ctx,
                " in testslab \"%V\"%Z", &shm_zone->shm.name);
    return NGX_OK;
}

static ngx_int_t ngx_http_testslab_init(ngx_conf_t* cf);
static char* ngx_http_testslab_createmem(ngx_conf_t* cf,
                                         ngx_command_t* cmd, void* conf);

static ngx_http_module_t ngx_http_testslab_module_ctx = {
    NULL,
    ngx_http_testslab_init,

    ngx_http_testslab_create_main_conf,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL
};

static ngx_command_t ngx_http_testslab_commands[] = {
    { ngx_string("test_slab"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,
      ngx_http_testslab_createmem,
      0,
      0,
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_testslab_module = {
    NGX_MODULE_V1,
    &ngx_http_testslab_module_ctx,
    ngx_http_testslab_commands,
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

static char*
ngx_http_testslab_createmem(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_testslab_conf_t* mconf = (ngx_http_testslab_conf_t*)conf;
    ngx_str_t name = ngx_string("test_slab_shm");
    ngx_str_t* value = (ngx_str_t*)cf->args->elts;

    mconf->interval = 1000 * ngx_atoi(value[1].data, value[1].len);
    if (mconf->interval == NGX_ERROR || mconf->interval == 0) {
        // -1 means turn off testslab
        mconf->interval = -1;
        return "invalid interval";
    }

    mconf->shmsize = ngx_parse_size(&value[2]);
    if (mconf->shmsize == (ssize_t)NGX_ERROR || mconf->shmsize == 0) {
        mconf->interval = -1;
        return "invalid shmsize";
    }

    ngx_shm_zone_t* shm_zone = ngx_shared_memory_add(cf, &name, mconf->shmsize,
                                                     &ngx_http_testslab_module);
    if (shm_zone == NULL) {
        mconf->interval = 1;
        return (char*)NGX_CONF_ERROR;
    }

    // Create node structure in init callback
    shm_zone->init = ngx_http_testslab_shm_init;
    shm_zone->data = mconf;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_testslab_handler(ngx_http_request_t* r) {
    ngx_http_testslab_conf_t* conf = (ngx_http_testslab_conf_t*)
            ngx_http_get_module_main_conf(r, ngx_http_testslab_module);
    ngx_int_t rc = NGX_DECLINED;

    if (conf->interval == -1) {
        return rc;
    }

    size_t len = r->connection->addr_text.len + r->uri.len;
    u_char* data = (u_char*)ngx_palloc(r->pool, len);
    ngx_memcpy(data, r->uri.data, r->uri.len);
    ngx_memcpy(data + r->uri.len, r->connection->addr_text.data,
               r->connection->addr_text.len);
    uint32_t hash = ngx_crc32_short(data, len);

    ngx_shmtx_lock(&conf->shpool->mutex);
    rc = ngx_http_testslab_lookup(r, conf, hash, data, len);
    ngx_shmtx_unlock(&conf->shpool->mutex);
    return rc;
}

static ngx_int_t ngx_http_testslab_init(ngx_conf_t* cf) {
    ngx_http_core_main_conf_t* cmcf = (ngx_http_core_main_conf_t*)
            ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    // Inject into NGX_HTTP_PREACCESS_PHASE
    ngx_http_handler_pt* h = (ngx_http_handler_pt*)
            ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_testslab_handler;
    return NGX_OK;
}

