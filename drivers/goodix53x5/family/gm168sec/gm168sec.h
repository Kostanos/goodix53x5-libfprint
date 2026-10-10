/*
 * Goodix 53x5 driver for libfprint — the GM168SEC family (27c6:533c)
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include "driver-private.h"

/* The prefix before the TLS records of a 0xb2 pack (image data). */
#define GOODIX_PACK_TLS_DATA_HDR   9

/* 533c ships with the all-zero PSK; this slot holds its SHA-256. */
#define GOODIX_WRAPPED_PSK_HASH_TYPE 0xbb020001
#define GOODIX_PSK_HASH_LEN          32

/* Fails without a firmware version, or with one that is not for the
 * GM168 or GM168SEC platform, as the vendor's SelfCheck does. */
GError *goodix_gm168sec_check_firmware (const char *firmware);
/* Returns a new SSM running the 533c bring-up. */
FpiSsm *goodix_gm168sec_open_new (FpDevice *dev);

/* Returns a new SSM for one TLS handshake attempt. */
FpiSsm *goodix_tls_attempt_new (FpDevice *dev);
/* Decrypts the TLS records of an image pack into raw12 bytes in @out. */
GoodixFrameStatus goodix_decrypt_frame_tls (FpiDeviceGoodix53x5 *self,
                                            const guint8 *payload, gsize len,
                                            guint8 **out, gsize *out_len);
