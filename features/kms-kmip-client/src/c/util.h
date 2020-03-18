/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * util.h
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <openssl/err.h>
#include <openssl/ssl.h>

BIO* initialize_tls_connection(SSL_CTX *ctx);
void free_tls_connection(BIO *bio, SSL_CTX *ctx);

#endif /* UTIL_H_ */
