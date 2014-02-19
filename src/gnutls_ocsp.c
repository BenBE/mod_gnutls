#include "mod_gnutls.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/ocsp.h>

#include <curl/curl.h>

#include <sys/stat.h>
#include <errno.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(gnutls);
#endif

static int
_generate_request (gnutls_datum_t * rdata, gnutls_x509_crt_t cert,
                   gnutls_x509_crt_t issuer);
static int
_perform_request (gnutls_datum_t *resp, gnutls_datum_t req, char *ocsp_provider_uri);
static size_t
get_data (void *buffer, size_t size, size_t nmemb, void *userp);
static int
_verify_response (gnutls_datum_t * data, gnutls_x509_crt_t cert,
                  gnutls_x509_crt_t signer, unsigned int* verify);

static char*
_x509_aia_ocsp_hostname(gnutls_x509_crt_t cert);



static int
_generate_request (gnutls_datum_t * rdata, gnutls_x509_crt_t cert,
                   gnutls_x509_crt_t issuer)
{
    gnutls_ocsp_req_t req;
    int ret;
    unsigned char noncebuf[23];
    gnutls_datum_t nonce = { noncebuf, sizeof (noncebuf) };

    ret = gnutls_ocsp_req_init (&req);
    if (ret < 0) {
        return 0;
    }

    ret = gnutls_ocsp_req_add_cert (req, GNUTLS_DIG_SHA1, issuer, cert);
    if (ret < 0) {
        return 0;
    }

    ret = gnutls_rnd (GNUTLS_RND_RANDOM, nonce.data, nonce.size);
    if (ret < 0) {
        return 0;
    }

    ret = gnutls_ocsp_req_set_nonce (req, 0, &nonce);
    if (ret < 0) {
        return 0;
    }

    ret = gnutls_ocsp_req_export (req, rdata);
    if (ret != 0) {
        return 0;
    }

    gnutls_ocsp_req_deinit (req);

    return 1;
}

static int
_perform_request (gnutls_datum_t *resp, gnutls_datum_t req, char *ocsp_provider_uri)
{
    CURL *handle;
    struct curl_slist *headers = NULL;
    int ret;

    if(!resp) {
        return 0;
    }
    resp->data = NULL;
    resp->size = 0;

    if(!ocsp_provider_uri) {
        return 0;
    }

    curl_global_init (CURL_GLOBAL_ALL);

    handle = curl_easy_init ();
    if (!handle) {
        return 0;
    }

    headers = curl_slist_append (headers, "Content-Type: application/ocsp-request");

    curl_easy_setopt (handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt (handle, CURLOPT_POSTFIELDS, (void *) req.data);
    curl_easy_setopt (handle, CURLOPT_POSTFIELDSIZE, req.size);
    curl_easy_setopt (handle, CURLOPT_URL, ocsp_provider_uri);
    curl_easy_setopt (handle, CURLOPT_WRITEFUNCTION, get_data);
    curl_easy_setopt (handle, CURLOPT_WRITEDATA, resp);

    ret = curl_easy_perform (handle);
    if (ret != 0) {
        return 0;
    }

    curl_easy_cleanup (handle);

    return 1;
}

static size_t
get_data (void *buffer, size_t size, size_t nmemb, void *userp)
{
    gnutls_datum_t *ud = userp;

    size *= nmemb;

    ud->data = realloc (ud->data, size + ud->size);
    if (ud->data == NULL) {
        return 0;
    }

    memcpy (&ud->data[ud->size], buffer, size);
    ud->size += size;

    return size;
}

static int
_verify_response (gnutls_datum_t * data, gnutls_x509_crt_t cert,
                  gnutls_x509_crt_t signer, unsigned int* verify)
{
    gnutls_ocsp_resp_t resp;
    int ret;
    unsigned int result;

    ret = gnutls_ocsp_resp_init (&resp);
    if (ret < 0) {
        return 0;
    }

    ret = gnutls_ocsp_resp_import (resp, data);
    if (ret < 0) {
        return 0;
    }

    ret = gnutls_ocsp_resp_check_crt (resp, 0, cert);
    if (ret < 0) {
        return 0;
    }

    ret = gnutls_ocsp_resp_verify_direct (resp, signer, &result, 0);
    if (ret < 0) {
        return 0;
    }

    if(verify) {
        *verify = result;
    }

    gnutls_ocsp_resp_deinit (resp);

    return 0 == result;
}

static char*
_x509_aia_ocsp_hostname(gnutls_x509_crt_t cert)
{
    int ret,seq;
    gnutls_datum_t tmp;
    char* result = NULL;

    /* Note that the OCSP servers hostname might be available
     * using gnutls_x509_crt_get_authority_info_access() in the issuer's
     * certificate */

    for (seq = 0; ; ++seq) {
        ret = gnutls_x509_crt_get_authority_info_access (cert, seq, GNUTLS_IA_OCSP_URI, &tmp, NULL);
        if (ret == GNUTLS_E_UNKNOWN_ALGORITHM) {
            continue;
        }

        if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            return NULL;
        }

        if (ret < 0) {
            return NULL;
        }

        result = malloc (tmp.size + 1);
        strncpy (result, (char*)tmp.data, tmp.size + 1);

        gnutls_free (tmp.data);
        break;
    }

    return result;
}

void
modgnutls_ocsp_response_update_cache(mgs_handle_t* ctxt, mgs_srvconf_rec *sc)
{
    /* For now, we will only proceed single-threaded */
    if(!ctxt || !sc) {
        return;
    }

    /* What's the internal server we belong to? */
    server_rec* s = ctxt->c->base_server;
    if(!s) {
        return;
    }

    /* Log we are doing some internal OCSP response querying */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
            "Updating certificate status information for '%s:%d'.",
            s->server_hostname, s->port);

    if(sc->certs_x509_chain_num < 2) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                "Cannot find certificate chain needed for OCSP status request for '%s:%d'.",
                s->server_hostname, s->port);
        return;
    }

    /* Assume first certificate is the leaf and the second being its issuer */
    /* Please note this somewhat enforces a cert chain with an intermediate certificate
       or the root certificate being transferred even though not needed. */
    gnutls_x509_crt_t cert = sc->certs_x509_chain[0];
    gnutls_x509_crt_t issuer = sc->certs_x509_chain[1];
    gnutls_x509_crt_t signer = sc->certs_x509_chain[1];

    gnutls_datum_t req;
    if(!_generate_request(&req, cert, issuer)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                "Failure when trying to create OCSP status request for '%s:%d'.",
                s->server_hostname, s->port);
        return;
    }

    char *ocsp_provider_uri = _x509_aia_ocsp_hostname(cert);
    if(!ocsp_provider_uri) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                "Failed to retrieve URI of OCSP status provider for '%s:%d'.",
                s->server_hostname, s->port);
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
            "Asking OCSP provider at URI %s for '%s:%d'.",
            ocsp_provider_uri, s->server_hostname, s->port);

    /* Perform the request */
    gnutls_datum_t resp;
    if(!_perform_request(&resp, req, ocsp_provider_uri)) {
        free(ocsp_provider_uri);

        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                "Failed to perform OCSP status request for '%s:%d'.",
                s->server_hostname, s->port);
        return;
    }

    free(ocsp_provider_uri);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
            "Received reply from OCSP provider for '%s:%d'.",
            s->server_hostname, s->port);

    /* Verify authenticity */
    {
        unsigned int verify = 0;
        int ret = _verify_response (&resp, cert, signer, &verify);

        if( !ret || (0 != verify) ) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "Signature verification of OCSP response failed for '%s:%d'.",
                    s->server_hostname, s->port);
            return;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "Signature validation succeeded; checking if response belongs to our OCSP status request for '%s:%d'.",
                s->server_hostname, s->port);

        {
            int resp_for_req = 0 == 0;

            gnutls_datum_t ocsp_req_nonce;
            gnutls_ocsp_req_t ocsp_req;

            gnutls_datum_t ocsp_resp_nonce;
            gnutls_ocsp_resp_t ocsp_resp;

            resp_for_req &= GNUTLS_E_SUCCESS == gnutls_ocsp_req_init(&ocsp_req);
            resp_for_req &= GNUTLS_E_SUCCESS == gnutls_ocsp_req_import (ocsp_req, &req);
            resp_for_req &= GNUTLS_E_SUCCESS == gnutls_ocsp_req_get_nonce(ocsp_req, NULL, &ocsp_req_nonce);
            gnutls_ocsp_req_deinit(ocsp_req);

            resp_for_req &= GNUTLS_E_SUCCESS == gnutls_ocsp_resp_init(&ocsp_resp);
            resp_for_req &= GNUTLS_E_SUCCESS == gnutls_ocsp_resp_import(ocsp_resp, &resp);
            resp_for_req &= GNUTLS_E_SUCCESS == gnutls_ocsp_resp_get_nonce(ocsp_resp, NULL, &ocsp_resp_nonce);
            gnutls_ocsp_resp_deinit(ocsp_resp);

            /* Both Nonce values should match */
            resp_for_req &= !memcmp(
                    ocsp_req_nonce.data,
                    ocsp_resp_nonce.data,
                    ocsp_req_nonce.size <= ocsp_resp_nonce.size ?
                        ocsp_req_nonce.size :
                        ocsp_resp_nonce.size
                    );

            if(ocsp_resp_nonce.data) {
                gnutls_free(ocsp_resp_nonce.data);
            }
            if(ocsp_req_nonce.data) {
                gnutls_free(ocsp_req_nonce.data);
            }

            if(!resp_for_req) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                        "OCSP response does not seem to match the OCSP request we sent for '%s:%d'.",
                        s->server_hostname, s->port);
                return;
            }
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
            "Reading information from response to update cache for '%s:%d'.",
            s->server_hostname, s->port);

    /* Read information from response */
    {
        apr_time_t ocsp_next_update = modgnutls_ocsp_response_get_next_update(resp);
        apr_time_t current_time = apr_time_now();
        sc->stapling_expire = current_time + apr_time_from_sec(60);

        if(current_time > ocsp_next_update) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "Received OCSP response already expired for '%s:%d'.",
                    s->server_hostname, s->port);
            return;
        }

        /* Write new OCSP response into configuration */
        gnutls_datum_t tmp;
        tmp.data = sc->stapling_response.data;
        tmp.size = sc->stapling_response.size;

        sc->stapling_response.data = NULL;
        sc->stapling_response.size = 0;

        sc->stapling_response.data = resp.data;
        sc->stapling_response.size = resp.size;

        free(tmp.data);

        if( current_time + apr_time_from_sec(300) > ocsp_next_update ) {
            sc->stapling_expire = ocsp_next_update;
        } else {
            sc->stapling_expire = current_time + apr_time_from_sec(300);
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
            "Cache update succeeded for '%s:%d'.",
            s->server_hostname, s->port);
}

apr_time_t
modgnutls_ocsp_response_get_next_update(gnutls_datum_t resp)
{
    gnutls_ocsp_resp_t _resp;
    int ret, index;
    apr_time_t earliest_update = 0;

    ret = gnutls_ocsp_resp_init (&_resp);
    if (ret < 0) {
        return 0;
    }

    ret = gnutls_ocsp_resp_import (_resp, &resp);
    if (ret < 0) {
        return 0;
    }

    for (index = 0; ; ++index) {
        time_t next_update;

        ret = gnutls_ocsp_resp_get_single (_resp, index, NULL /* digest */, NULL /* in */, NULL /* ik */, NULL /* sn */, NULL /* cert_status */, NULL /* this_update */, &next_update, NULL /* revocation_time */, NULL /* revocation_reason */);
        if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            break;
        }

        if (ret != GNUTLS_E_SUCCESS) {
            continue;
        }

        if(!earliest_update) {
            earliest_update = apr_time_from_sec(next_update);
        } else if(earliest_update > apr_time_from_sec(next_update)) {
            earliest_update = apr_time_from_sec(next_update);
        }
    }

    gnutls_ocsp_resp_deinit (_resp);

    return earliest_update;
}
