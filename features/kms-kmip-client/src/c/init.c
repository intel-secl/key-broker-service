/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * init.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include "common.h"
#include "logging.h"

char server_address[2048];
char server_port[6];
char client_certificate[PATH_MAX];
char client_key[PATH_MAX];
char ca_certificate[PATH_MAX];
FILE *log_fp;

int kmipw_init(const char *address, const char *port, const char *certificate, const char *key, const char *ca) {
    log_fp = configure_logger();
    if (log_fp == NULL) {
          printf("Failed to configure logger\n");
          fclose(log_fp);
          return -1;
    }

    if (address == NULL) {
        log_error("KMIP server address is not provided.\n");
        fclose(log_fp);
        return -1;
    }

    if (port == NULL) {
        log_error("KMIP server port is not provided.\n");
        fclose(log_fp);
        return -1;
    }

    if (certificate == NULL) {
        log_error("KMIP client certificate is not provided.\n");
        fclose(log_fp);
        return -1;
    }

    if (key == NULL) {
        log_error("KMIP client key is not provided.\n");
        fclose(log_fp);
        return -1;
    }

    if (ca == NULL) {
        log_error("KMIP ca certificate is not provided.\n");
        fclose(log_fp);
        return -1;
    }

    strncpy(server_address, address, strnlen(address, sizeof(server_address)));
    strncpy(server_port, port, strnlen(port, sizeof(server_port)));
    strncpy(client_certificate, certificate, strnlen(certificate, sizeof(client_certificate)));
    strncpy(client_key, key, strnlen(key, sizeof(client_key)));
    strncpy(ca_certificate, ca, strnlen(ca, sizeof(ca_certificate)));
    fclose(log_fp);
    return 0;
}
