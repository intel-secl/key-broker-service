/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * get.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "util.h"
#include "logging.h"

extern FILE *log_fp;
/*
* get:
*
* @id: unique identifier of the object to be retrieved
*/


char* kmipw_get(const char *id) {
    log_fp = configure_logger();
    if (log_fp == NULL) {
        printf("Failed to configure logger\n");
        return NULL;
    }

    log_debug("kmipw_get called");
    log_debug("get key for id: %s", id);

    SSL_CTX *ctx = NULL;
    BIO *bio = NULL;
    char *key = NULL;
    bio = initialize_tls_connection(ctx);
    if(bio == NULL)
    {
        log_error("BIO_new_ssl_connect failed");
        ERR_print_errors_fp(log_fp);
        fclose(log_fp);
        return NULL;
    }

    /* Set up the KMIP context. */
    KMIP kmip_ctx = {0};
    kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);

    int key_size = 0;
    size_t id_size = kmip_strnlen_s(id, 50);

    /* Send the request message. */
    int result = kmip_bio_get_symmetric_key_with_context(&kmip_ctx, bio, id, id_size, &key, &key_size);

    free_tls_connection(bio, ctx);

    /* Handle the response results. */
    if(result < 0)
    {
        log_error("An error occurred while creating the symmetric key.");
        log_error("Error Code: %d", result);
        kmip_print_error_string(result);
        log_error("Context Error: %s", kmip_ctx.error_message);
        log_error("Stack trace:\n");
        kmip_print_stack_trace(&kmip_ctx);
    }
    else if(result >= 0)
    {
        log_info("The KMIP operation was executed with no errors.\n");
        kmip_print_result_status_enum(result);
        log_info("Result (%d)", result);
        
        if(result == KMIP_STATUS_SUCCESS)
        {
            log_debug("Symmetric Key ID: %s\n", id);
            log_debug("Symmetric Key Size: %d bits\n", key_size * 8);
            kmip_print_buffer(key, key_size);
        }
    }
    
    /* Clean up the KMIP context and return the results. */
    fclose(log_fp);
    kmip_destroy(&kmip_ctx);
    return key;
}
