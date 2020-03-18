/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * create.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "util.h"
#include "logging.h"

extern FILE *log_fp;

/*
* create:
*
* @alg_id: algorithm identifier of the key to be created
*
* @alg_length: length of the key to be created
*/
char* kmipw_create(int alg_id, int alg_length) {
    const char *key_uuid;
    log_fp = configure_logger();
    if (log_fp == NULL) {
        printf("Failed to configure logger\n");
        return NULL;
    }
    log_info("kmipw_create called");
    SSL_CTX *ctx = NULL;
    BIO *bio = NULL;
    bio = initialize_tls_connection(ctx);
    if(bio == NULL)
    {
        log_error("BIO_new_ssl_connect failed.");
        ERR_print_errors_fp(log_fp);
        fclose(log_fp);
        return NULL;
    }
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP kmip_ctx = {0};
    kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);
    
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;
    
    uint8 *encoding = kmip_ctx.calloc_func(kmip_ctx.state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(&kmip_ctx);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        fclose(log_fp);
        return NULL;
    }
    kmip_set_buffer(&kmip_ctx, encoding, buffer_total_size);
    /* Build the request message. */
    Attribute a[4] = {0};
    for(int i = 0; i < 4; i++)
        kmip_init_attribute(&a[i]);
    
    enum cryptographic_algorithm algorithm = alg_id;
    a[0].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    a[0].value = &algorithm;
    
    int32 length = alg_length;
    a[1].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    a[1].value = &length;
    
    CryptographicParameters cp = {0};
    kmip_init_cryptographic_parameters(&cp);
    enum block_cipher_mode mode = KMIP_BLOCK_GCM;
    cp.block_cipher_mode = mode;
    a[2].type = KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS;
    a[2].value = &cp;
    
    int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
    a[3].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    a[3].value = &mask;
    LinkedList *list = kmip_ctx.calloc_func(kmip_ctx.state, 1, sizeof(LinkedList));
    if(list != NULL)
    {
        LinkedListItem *item0 = kmip_ctx.calloc_func(kmip_ctx.state, 1, sizeof(LinkedListItem));
        if(item0 != NULL)
        {
    	    item0->data = &a[0];
	        kmip_linked_list_push(list, item0);
        }
    
        LinkedListItem *item1 = kmip_ctx.calloc_func(kmip_ctx.state, 1, sizeof(LinkedListItem));
        if(item1 != NULL)
        {
    	    item1->data = &a[1];
	        kmip_linked_list_push(list, item1);
        }
    
        LinkedListItem *item2 = kmip_ctx.calloc_func(kmip_ctx.state, 1, sizeof(LinkedListItem));
        if(item2 != NULL)
        {
    	    item2->data = &a[2];
	        kmip_linked_list_push(list, item2);
        }
    
        LinkedListItem *item3 = kmip_ctx.calloc_func(kmip_ctx.state, 1, sizeof(LinkedListItem));
        if(item3 != NULL)
        {
    	    item3->data = &a[3];
	        kmip_linked_list_push(list, item3);
        }
    }
    Attributes attrs = {0};
    attrs.attribute_list = list;
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, kmip_ctx.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = kmip_ctx.max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;
    
    CreateRequestPayload crp = {0};
    crp.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    crp.attributes = &attrs;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_CREATE;
    rbi.request_payload = &crp;
    
    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;
    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(&kmip_ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(&kmip_ctx);
        kmip_ctx.free_func(kmip_ctx.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
          
        encoding = kmip_ctx.calloc_func(kmip_ctx.state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            log_error("Failure: Could not automatically enlarge the encoding buffer for the Create request.");
            kmip_destroy(&kmip_ctx);
            free_tls_connection(bio, ctx);
            fclose(log_fp);
            return NULL;
        }
        kmip_set_buffer(&kmip_ctx, encoding, buffer_total_size);
        encode_result = kmip_encode_request_message(&kmip_ctx, &rm);
    }
    if(encode_result != KMIP_OK)
    {
        log_error("An error occurred while encoding the Create request.");
        log_error("Error Code: %d", encode_result);
        log_error("Error Name: ");
        kmip_print_error_string(encode_result);
        log_error("Context Error: %s\n", kmip_ctx.error_message);
        log_error("Stack trace:");
        kmip_print_stack_trace(&kmip_ctx);

        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(&kmip_ctx, NULL, 0);
        kmip_destroy(&kmip_ctx);
        free_tls_connection(bio, ctx);
        fclose(log_fp);
        return NULL;
    }
    kmip_print_request_message(&rm);
    char *response = NULL;
    int response_size = 0;
    
    int result = kmip_bio_send_request_encoding(&kmip_ctx, bio, (char *)encoding, kmip_ctx.index - kmip_ctx.buffer, &response, &response_size);
    
    free_tls_connection(bio, ctx);
    printf("\n");
    if(result < 0)
    {
        log_error("An error occurred while creating the symmetric key.");
        log_error("Error Code: %d", result);
        log_error("Error Name: ");
        kmip_print_error_string(result);
        log_error("Context Error: %s", kmip_ctx.error_message);
        log_error("Stack trace:");
        kmip_print_stack_trace(&kmip_ctx);
        
        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        encoding = NULL;
	key_uuid = NULL;
        goto final;
    }
    kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(&kmip_ctx, response, response_size);
    
    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(&kmip_ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        log_error("An error occurred while decoding the Create response.");
        log_error("Error Code: %d", decode_result);
        log_error("Error Name: ");
        kmip_print_error_string(decode_result);
        log_error("Context Error: %s", kmip_ctx.error_message);
        log_error("Stack trace:");
        kmip_print_stack_trace(&kmip_ctx);

        kmip_free_response_message(&kmip_ctx, &resp_m);
        result = decode_result;
	key_uuid = NULL;
        goto final;
    }
    kmip_print_response_message(&resp_m);

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        log_info("Expected to find one batch item in the Create response.");
        kmip_free_response_message(&kmip_ctx, &resp_m);
        result = KMIP_MALFORMED_RESPONSE;
        goto final;
    }
    
    ResponseBatchItem req = resp_m.batch_items[0];
    enum result_status result_status = req.result_status;
    log_info("The KMIP operation was executed with no errors.");
    log_info("Result: %d", result);
    kmip_print_result_status_enum(result);
    if(result == KMIP_STATUS_SUCCESS)
    {
        CreateResponsePayload *pld = (CreateResponsePayload *)req.response_payload;
        if(pld != NULL)
        {
            TextString *uuid = pld->unique_identifier;
            
            if(uuid != NULL){
		key_uuid = uuid->value;
            }
        }
    }
    result = result_status;
final:
    /* Clean up the response message, the response buffer, and the KMIP */
    /* context.                                                         */
    kmip_free_buffer(&kmip_ctx, response, response_size);
    response = NULL;
    kmip_set_buffer(&kmip_ctx, NULL, 0);
    kmip_destroy(&kmip_ctx);
    fclose(log_fp);
    return key_uuid;
}
