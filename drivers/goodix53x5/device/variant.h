/*
 * Goodix 53x5 driver for libfprint — sensor variants
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <glib.h>

typedef struct _FpDevice FpDevice;
typedef struct _FpiSsm FpiSsm;
typedef struct _FpiDeviceGoodix53x5 FpiDeviceGoodix53x5;
typedef struct _GoodixTransport GoodixTransport;

typedef enum
{
  /* Decrypted by the established session. */
  GOODIX_FRAME_DECRYPTED,
  /* Rejected before the session was established; says nothing about the session. */
  GOODIX_FRAME_REJECTED,
  /* Rejected on an established session; counts towards restarting it. */
  GOODIX_FRAME_REJECTED_IN_SESSION,
} GoodixFrameStatus;

/* The one place the sensor families this driver runs differ: same chip and
 * pipeline, but their own USB framing and secure channel. The transport and
 * session ask the device's variant rather than branch on its USB id. */
typedef struct
{
  /* The secure channel's name in logs. */
  const char *channel_name;
  guint8      usb_interface;
  guint8      ep_in;
  guint8      ep_out;
  /* Bytes of the chip-ID register read; the first four agree across both. */
  gsize       chip_id_request_len;
  /* The preset slot holding the SHA-256 of the sensor's PSK. */
  guint32     psk_hash_type;
  /* FALSE where a failed PSK or production write could not be recovered
   * from, so the driver never writes one. */
  gboolean    provisionable;
  /* TRUE where some commands are answered with the reply alone, no ACK. */
  gboolean    reply_implies_ack;
  /* TRUE where starting a new secure-channel session drops the
   * finger-detect arm, so a scan arms again after a channel restart. */
  gboolean    channel_restart_disarms;
  /* TRUE where one undecodable image restarts the secure channel, as an
   * OpenSSL session is dead after a failed record; GTLS waits for a second. */
  gboolean    restart_on_first_image_error;

  /* Requests the PSK hash; goodix_cmd_parse_psk_hash_reply() reads it. */
  void              (*read_psk_hash) (FpiSsm *ssm, FpDevice *dev);
  /* Returns a new SSM for one secure-channel handshake attempt. */
  FpiSsm           *(*new_channel_attempt) (FpDevice *dev);
  /* Returns the bytes to write for the protocol message @msg. */
  guint8           *(*frame) (const guint8 *msg, gsize msg_len, gsize *out_len);
  /* Returns the bytes to write for a raw TLS record; NULL on a variant
   * without a TLS channel. */
  guint8           *(*frame_record) (GBytes *record, gsize *out_len);
  /* Hands the bytes of one completed IN transfer to the receiver. */
  void              (*receive) (FpiDeviceGoodix53x5 *self,
                                GoodixTransport *operation,
                                const guint8 *data, gsize len);
  /* Decrypts an encrypted image payload into raw12 bytes in @out. */
  GoodixFrameStatus (*decrypt_frame) (FpiDeviceGoodix53x5 *self,
                                      const guint8 *payload, gsize len,
                                      guint8 **out, gsize *out_len);
} GoodixVariant;

/* 5335/5385/5395: direct framing on interface 1, GTLS. */
extern const GoodixVariant goodix_variant_direct;
/* 533c: wrapped framing on interface 0, TLS 1.2-PSK. */
extern const GoodixVariant goodix_variant_wrapped;
