/* ====================================================================
 *  Copyright 2004 Paul Querna
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

#ifndef __mod_gnutls_h_inc
#define __mod_gnutls_h_inc

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_buckets.h"
#include "apr_strings.h"
#include "apr_tables.h"

#include <gcrypt.h>
#include <gnutls/gnutls.h>

module AP_MODULE_DECLARE_DATA gnutls_module;

#define GNUTLS_OUTPUT_FILTER_NAME "gnutls_output_filter"
#define GNUTLS_INPUT_FILTER_NAME "gnutls_input_filter"

#define GNUTLS_ENABLED_FALSE 0
#define GNUTLS_ENABLED_TRUE  1


/**
 * GnuTLS changed the names of several structures between 1.0.X and 1.1.X 
 * This is just a simple hack so we can compile with both versions.
 * There is a full list in <gnutls/compat.h>, But I am just 
 * doing this for a few types we use.
 */
#ifndef gnutls_certificate_credentials_t
#define gnutls_certificate_credentials_t    gnutls_certificate_credentials
#define gnutls_anon_server_credentials_t    gnutls_anon_server_credentials
#define gnutls_session_t                    gnutls_session
#define gnutls_transport_ptr_t              gnutls_transport_ptr
#define gnutls_dh_params_t                  gnutls_dh_params
#define gnutls_rsa_params_t                 gnutls_rsa_params
#endif

typedef struct
{
    gnutls_certificate_credentials_t certs;
    gnutls_anon_server_credentials_t anoncred;
    char *key_file;
    char *cert_file;
    int enabled;
    int ciphers[16];
    int key_exchange[16];
    int macs[16];
    int protocol[16];
    int compression[16];
} mod_gnutls_srvconf_rec;

typedef struct {
    int length;
    char *value;
} mod_gnutls_char_buffer_t;

typedef struct
{
    mod_gnutls_srvconf_rec *sc;
    conn_rec* c;
    gnutls_session_t session;

    apr_status_t input_rc;
    ap_filter_t *input_filter;
    apr_bucket_brigade *input_bb;
    apr_read_type_e input_block;
    ap_input_mode_t input_mode;
    mod_gnutls_char_buffer_t input_cbuf;
    char input_buffer[AP_IOBUFSIZE];

    apr_status_t output_rc;
    ap_filter_t *output_filter;
    apr_bucket_brigade *output_bb;
    char output_buffer[AP_IOBUFSIZE];
    apr_size_t output_blen;
    apr_size_t output_length;

    int status;
    int non_https;
} mod_gnutls_handle_t;

/** Functions in gnutls_io.c **/

/**
 * mod_gnutls_filter_input will filter the input data
 * by decrypting it using GnuTLS and passes it cleartext.
 *
 * @param f     the filter info record
 * @param bb    the bucket brigade, where to store the result to
 * @param mode  what shall we read?
 * @param block a block index we shall read from?
 * @return result status
 */
apr_status_t mod_gnutls_filter_input(ap_filter_t * f,
                                     apr_bucket_brigade * bb,
                                     ap_input_mode_t mode,
                                     apr_read_type_e block,
                                     apr_off_t readbytes);

/**
 * mod_gnutls_filter_output will filter the encrypt
 * the incoming bucket using GnuTLS and passes it onto the next filter.
 *
 * @param f     the filter info record
 * @param bb    the bucket brigade, where to store the result to
 * @return result status
 */
apr_status_t mod_gnutls_filter_output(ap_filter_t * f,
                                      apr_bucket_brigade * bb);


/**
 * mod_gnutls_transport_read is called from GnuTLS to provide encrypted 
 * data from the client.
 *
 * @param ptr     pointer to the filter context
 * @param buffer  place to put data
 * @param len     maximum size
 * @return size   length of the data stored in buffer
 */
ssize_t mod_gnutls_transport_read(gnutls_transport_ptr_t ptr,
                                  void *buffer, size_t len);

/**
 * mod_gnutls_transport_write is called from GnuTLS to 
 * write data to the client.
 *
 * @param ptr     pointer to the filter context
 * @param buffer  buffer to write to the client
 * @param len     size of the buffer
 * @return size   length of the data written
 */
ssize_t mod_gnutls_transport_write(gnutls_transport_ptr_t ptr,
                                   const void *buffer, size_t len);


#endif /*  __mod_gnutls_h_inc */
