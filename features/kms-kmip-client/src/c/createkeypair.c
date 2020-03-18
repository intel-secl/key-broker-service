/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * createkeypair.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "util.h"

/*
* createkeypair:
*
* @alg_id: algorithm identifier of the key to be created
*
* @alg_length: length of the key to be created
*/
int createkeypair(int alg_id, int alg_length) {

    SSL_CTX *ctx = NULL;
    BIO *bio = NULL;

    BIO *bio = initialize_tls_connection(ctx);
    if(bio == NULL)
    {
        fprintf(stderr, "BIO_new_ssl_connect failed\n");
        ERR_print_errors_fp(stderr);
        return bio;
    }

    /* Set up the KMIP context. */
    KMIP kmip_ctx = {0};
    kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);

    Attribute a[4] = {0};
    for(int i = 0; i < 4; i++)
        kmip_init_attribute(&a[i]);
    
    enum cryptographic_algorithm algorithm = alg_id;
    a[0].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    a[0].value = &algorithm;
    
    int32 length = alg_length;
    a[1].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    a[1].value = &length;

    LinkedList *list = kmip_context.calloc_func(kmip_context.state, 1, sizeof(LinkedList));
    if(list != NULL)
    {
        LinkedListItem *item0 = kmip_context.calloc_func(kmip_context.state, 1, sizeof(LinkedListItem));
        if(item0 != NULL)
        {
    	    item0->data = &a[0];
	    kmip_linked_list_push(list, item0);
        }
    
        LinkedListItem *item1 = kmip_context.calloc_func(kmip_context.state, 1, sizeof(LinkedListItem));
        if(item1 != NULL)
        {
    	    item1->data = &a[1];
	    kmip_linked_list_push(list, item1);
        }
    }

    Attributes attrs = {0};
    attrs.attribute_list = list;

    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, kmip_context.version);
    
    RequestHeader rh = {0};
    kmip_init_request_header(&rh);
    
    rh.protocol_version = &pv;
    rh.maximum_response_size = kmip_context.max_message_size;
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
        kmip_context.free_func(kmip_ctx.state, encoding);
        
        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;
        
        encoding = kmip_ctx.calloc_func(kmip_ctx.state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            printf("Failure: Could not automatically enlarge the encoding ");
            printf("buffer for the Create request.\n");

            kmip_destroy(&kmip_ctx);
            free_tls_connection(bio, ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        
        kmip_set_buffer(&kmip_ctx, encoding, buffer_total_size);
        encode_result = kmip_encode_request_message(&kmip_ctx, &rm);
    }
    
    if(encode_result != KMIP_OK)
    {
        printf("An error occurred while encoding the Create request.\n");
        printf("Error Code: %d\n", encode_result);
        printf("Error Name: ");
        kmip_print_error_string(encode_result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(&kmip_ctx);

        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(&kmip_ctx, NULL, 0);
        kmip_destroy(&kmip_ctx);
        free_tls_connection(bio, ctx);
        return(encode_result);
    }
    
    kmip_print_request_message(&rm);
    printf("\n");
    
    char *response = NULL;
    int response_size = 0;
    
    int result = kmip_bio_send_request_encoding(&kmip_ctx, bio, (char *)encoding, kmip_context.index - kmip_context.buffer, &response, &response_size);
    
    free_tls_connection(bio, ctx, &kmip_ctx);
    
    printf("\n");
    if(result < 0)
    {
        printf("An error occurred while creating the symmetric key.\n");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        kmip_print_error_string(result);
        printf("\n");
        printf("Context Error: %s\n", kmip_ctx.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(&kmip_ctx);
        
        kmip_free_buffer(&kmip_ctx, encoding, buffer_total_size);
        encoding = NULL;
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
        printf("An error occurred while decoding the Create response.\n");
        printf("Error Code: %d\n", decode_result);
        printf("Error Name: ");
        kmip_print_error_string(decode_result);
        printf("\n");
        printf("Context Error: %s\n", kmip_ctx.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(&kmip_ctx);

        kmip_free_response_message(&kmip_ctx, &resp_m);
        result = decode_result;
        goto final;
    }
    
    kmip_print_response_message(&resp_m);
    printf("\n");

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        printf("Expected to find one batch item in the Create response.\n");
        kmip_free_response_message(&kmip_ctx, &resp_m);
        result = KMIP_MALFORMED_RESPONSE;
        goto final;
    }
    
    ResponseBatchItem req = resp_m.batch_items[0];
    enum result_status result_status = req.result_status;
    
    printf("The KMIP operation was executed with no errors.\n");
    printf("Result: ");
    kmip_print_result_status_enum(result);
    printf(" (%d)\n\n", result);
    
    if(result == KMIP_STATUS_SUCCESS)
    {
        CreateResponsePayload *pld = (CreateResponsePayload *)req.response_payload;
        if(pld != NULL)
        {
            TextString *uuid = pld->unique_identifier;
            
            if(uuid != NULL)
                printf("Symmetric Key ID: %.*s\n", (int)uuid->size, uuid->value);
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
    
    return(result);
}
