/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.kms.stmlib;

import com.sun.jna.Library;
import com.sun.jna.Native;

/**
 * SslLibrary interface loads libssl.so lib into JNA layer
 *
 * @author rbhat
 */
public interface SslLibrary extends Library { 
    static SslLibrary SSL_INSTANCE = (SslLibrary)Native.loadLibrary("ssl", SslLibrary.class);
}
