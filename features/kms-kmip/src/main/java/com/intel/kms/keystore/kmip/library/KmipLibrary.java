/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.keystore.kmip.library;

import com.sun.jna.Library;
import java.lang.String;

public interface KmipLibrary extends Library {

    // define list of functions to be accessed from libkmipclient
    public int kmipw_init(String address, String port, String certificatePath, String keyPath, String caCertPath);
    public int kmipw_get(String uuid, String keyid);
    public int kmipw_destroy(String uuid);
    public String kmipw_create(int alg_id, int alg_length);
}

