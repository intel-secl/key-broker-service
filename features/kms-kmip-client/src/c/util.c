/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * util.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "util.h"
#include "logging.h"

extern char server_address[2048];
extern char server_port[6];
extern char client_certificate[PATH_MAX];
extern char client_key[PATH_MAX];
extern char ca_certificate[PATH_MAX];
extern FILE *log_fp;

/*
* initialize_tls_connection:
*
* @ctx: SSL context
*
* Returns the tls connection to the KMIP server
*/
BIO* initialize_tls_connection(SSL_CTX *ctx) {
    /* Set up the TLS connection to the KMIP server. */
    BIO *bio = NULL;
    SSL *ssl = NULL;
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());

    log_info("Loading the client certificate: %s", client_certificate);
    if(SSL_CTX_use_certificate_file(ctx, client_certificate, SSL_FILETYPE_PEM) != 1)
    {
        log_error("Loading the client certificate failed");
        goto final;
    }

    log_info("Loading the client key: %s", client_key);
    if(SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1)
    {
        log_error("Loading the client key failed");
        goto final;
    }
    
    log_info("Loading the CA certificate: %s", ca_certificate);
    if(SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL) != 1)
    {
        log_error("Loading the CA certificate failed");
        goto final;
    }

    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        log_error("BIO_new_ssl_connect failed");
        goto final;
    }

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);
    if(BIO_do_connect(bio) != 1)
    {
        log_error("BIO_do_connect failed");
        BIO_free_all(bio);
        bio = NULL;
        goto final;
    }
final:
    ERR_print_errors_fp(log_fp);
    SSL_CTX_free(ctx);
    return bio;
}

/*
* free_tls_connection:
*
* @bio: 
*
* @ctx: 
*
* Cleanup the tls connection
*/
void free_tls_connection(BIO *bio, SSL_CTX *ctx) {

    if (bio) BIO_free_all(bio);
    if (ctx) SSL_CTX_free(ctx);
}
