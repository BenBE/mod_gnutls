/**
 *  Copyright 2004-2005 Paul Querna
 *  Copyright 2008 Nikos Mavrogiannopoulos
 *  Copyright 2011 Dash Shendy
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include "mod_gnutls.h"

#include <unistd.h>
#include <sys/types.h>

#if !defined(OS2) && !defined(WIN32) && !defined(BEOS) && !defined(NETWARE)
#include "unixd.h"
#endif

/* it seems the default has some strange errors. Use SDBM
 */
#define MC_TAG "mod_gnutls"

#if MODULE_MAGIC_NUMBER_MAJOR < 20081201
#define ap_unixd_config unixd_config
#endif

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

char *mgs_util_bin2hex_p(apr_pool_t *p, char *buf, int len) {
    static const char *hexdigits = "0123456789ABCDEF";

    apr_size_t i;

    char *result = apr_pcalloc(p, 1 + 2 * len);
    if(!result) {
        return result;
    }

    for(i = 0; i < len; i++) {
        result[2*i+0] = hexdigits[(buf[i] >> 4) & 0x0F];
        result[2*i+1] = hexdigits[(buf[i] >> 0) & 0x0F];
    }

    result[2*len] = 0;
    return result;
}

/* Name the Session ID as:
 * server:port:SessionID
 * to disallow resuming sessions on different servers
 */
int mgs_session_id2sz(conn_rec *c, char *id, int idlen, gnutls_datum_t *key) {
    char *sz = mgs_util_bin2hex_p(c->pool, id, idlen);

    if (sz == NULL) {
        return -1;
    }

    key->data = (unsigned char *)apr_psprintf(c->pool,
            MC_TAG ":session:" "%s:%04X:%s",
            c->base_server->server_hostname,
            c->base_server->port, sz);
    key->size = strlen((char *)key->data);

    if(!key->data) {
        return -1;
    }

    return 0;
}

#define CTIME "%b %d %k:%M:%S %Y %Z"

char *mgs_time2sz(time_t in_time, char *str, int strsize) {
    apr_time_exp_t vtm;
    apr_size_t ret_size;
    apr_time_t t;

    apr_time_ansi_put(&t, in_time);
    apr_time_exp_gmt(&vtm, t);
    apr_strftime(str, &ret_size, strsize - 1, CTIME, &vtm);

    return str;
}

/**
 * Generic low-level cache interface
 */

int mgs_cache_store(mgs_handle_t *ctxt, gnutls_datum_t key, gnutls_datum_t data, apr_time_t expire) {
    if(!ctxt->sc) {
        return APR_EGENERAL;
    }

    if(!ctxt->sc->cache_provider || !ctxt->sc->cache_context) {
        return APR_EGENERAL;
    }

    if(0 == expire) {
        expire = apr_time_now() + apr_time_sec(ctxt->sc->cache_timeout);
    }

    return ctxt->sc->cache_provider->store(
        ctxt->sc->cache_context,
        ctxt->c->base_server,
        key.data,
        key.size,
        expire,
        data.data,
        data.size,
        ctxt->c->pool
        );
}

gnutls_datum_t mgs_cache_fetch(mgs_handle_t *ctxt, gnutls_datum_t key, apr_time_t* expire) {
    gnutls_datum_t data = {NULL, 0};

    if(expire) {
        *expire = 0;
    }

    if(!ctxt->sc) {
        return data;
    }

    if(!ctxt->sc->cache_provider || !ctxt->sc->cache_context) {
        return data;
    }

    data.size = 65536;
    data.data = apr_pcalloc(ctxt->c->pool, data.size);

    int rv = ctxt->sc->cache_provider->retrieve(
        ctxt->sc->cache_context,
        ctxt->c->base_server,
        key.data,
        key.size,
        data.data,
        &data.size,
        ctxt->c->pool
        );

    if(APR_SUCCESS != rv) {
        data.data = NULL;
        data.size = 0;
    }

    return data;
}

int mgs_cache_delete(mgs_handle_t *ctxt, gnutls_datum_t key) {
    if(!ctxt->sc) {
        return APR_EGENERAL;
    }

    if(!ctxt->sc->cache_provider || !ctxt->sc->cache_context) {
        return APR_EGENERAL;
    }

    return ctxt->sc->cache_provider->remove(
        ctxt->sc->cache_context,
        ctxt->c->base_server,
        key.data,
        key.size,
        ctxt->c->pool
        );
}

int mgs_cache_post_config(apr_pool_t * p, server_rec * s,
        mgs_srvconf_rec * sc) {

    /* if GnuTLSCache was never explicitly set: */
    if (sc->cache_type == mgs_cache_unset) {
        sc->cache_type = mgs_cache_none;
    }
    /* if GnuTLSCacheTimeout was never explicitly set: */
    if (sc->cache_timeout == -1) {
        sc->cache_timeout = apr_time_from_sec(300);
    }

    if (!sc->cache_provider) {
        sc->cache_type = mgs_cache_none;
    }

    if (!sc->cache_context) {
        sc->cache_type = mgs_cache_none;
    }

    if (sc->cache_type != mgs_cache_none) {
//        return dbm_cache_post_config(p, s, sc);
        sc->cache_provider->init(sc->cache_context, MC_TAG, NULL, s, p);
        return 0;
    }
    return 0;
}

int mgs_cache_child_init(apr_pool_t * p, server_rec * s, mgs_srvconf_rec * sc) {
    if (sc->cache_type != mgs_cache_none) {
        return 0;
    }

    return 0;
}

static gnutls_datum_t mgs_cache_session_fetch(void *baton, gnutls_datum_t key) {
    gnutls_datum_t data = {NULL, 0};

    mgs_handle_t *ctxt = baton;
    if(!ctxt) {
        return data;
    }

    gnutls_datum_t session_id = {NULL, 0};
    if(0 > mgs_session_id2sz(ctxt->c, (char*)key.data, key.size, &session_id)) {
        return data;
    }

    return mgs_cache_fetch(ctxt, session_id, NULL);
}

static int mgs_cache_session_store(void *baton, gnutls_datum_t key, gnutls_datum_t data) {
    mgs_handle_t *ctxt = baton;
    if(!ctxt) {
        return -1;
    }

    gnutls_datum_t session_id = {NULL, 0};
    if(0 > mgs_session_id2sz(ctxt->c, (char*)key.data, key.size, &session_id)) {
        return -1;
    }

    return mgs_cache_store(ctxt, session_id, data, 0);
}

static int mgs_cache_session_delete(void *baton, gnutls_datum_t key) {
    mgs_handle_t *ctxt = baton;
    if(!ctxt) {
        return -1;
    }

    gnutls_datum_t session_id = {NULL, 0};
    if(0 > mgs_session_id2sz(ctxt->c, (char*)key.data, key.size, &session_id)) {
        return -1;
    }

    return mgs_cache_delete(ctxt, session_id);
}

int mgs_cache_session_init(mgs_handle_t * ctxt) {
    if (ctxt->sc->cache_type) {
        gnutls_db_set_retrieve_function(ctxt->session,
                mgs_cache_session_fetch);
        gnutls_db_set_remove_function(ctxt->session,
                mgs_cache_session_delete);
        gnutls_db_set_store_function(ctxt->session,
                mgs_cache_session_store);
        gnutls_db_set_ptr(ctxt->session, ctxt);
    }

    return 0;
}
