/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * destroy.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "util.h"
#include "logging.h"

extern FILE *log_fp;
/*
* destroy:
*
* @id: unique identifier of the object to be destroyed
*/
int kmipw_destroy(const char *id) {
    log_fp = configure_logger();
    if (log_fp == NULL) {
        printf("Failed to configure logger\n");
        return -1;
    }
    log_info("kmipw_destroy called");
    log_debug("key id: %s", id);
    SSL_CTX *ctx = NULL;
    BIO *bio = NULL;

    bio = initialize_tls_connection(ctx);
    
    if(bio == NULL)
    {
        log_error("BIO_new_ssl_connect failed");
        ERR_print_errors_fp(log_fp);
        fclose(log_fp);
        return -1;
    }
    /* Set up the KMIP context. */
    KMIP kmip_ctx = {0};

    kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);

    /* Send the request message. */
    int result = kmip_bio_destroy_symmetric_key_with_context(&kmip_ctx, bio, id, kmip_strnlen_s(id, 50));

    free_tls_connection(bio, ctx);
    /* Handle the response results. */
    if(result < 0)
    {
        log_error("An error occurred while deleting object: %s", id);
        log_error("Error Code: %d", result);
    }
    else
    {
        log_info("The KMIP operation was executed with no errors.");
        log_info("Result: %d", result);
        kmip_print_result_status_enum(result);
    }

    /* Clean up the KMIP context and return the results. */
    fclose(log_fp);
    kmip_destroy(&kmip_ctx);
    return(result);
}
