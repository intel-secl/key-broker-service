/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.barbican.api;

/**
 * Represents response to {@code POST /v1/orders}
 * 
 * @author soak
 */
public class CreateOrderResponse {
    public String order_ref; // URL "http://localhost:8080/v1/orders/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718"
}
