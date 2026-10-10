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
  /* Decrypted, but not an image; the session that decrypted it is sound. */
  GOODIX_FRAME_INVALID,
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
  /* The EC-control payload that isolates the power button while the sensor
   * scans; every variant ends isolation with three zero bytes. */
  guint8      ec_on_payload[3];
  /* Bytes of the wake NOP's zero payload. */
  gsize       wake_payload_len;
  /* The firmware-version reads open attempts before giving up on the version. */
  guint       firmware_reads;
  /* TRUE where open fails without a firmware version, as SelfCheck needs one;
   * 53x5 native continues without it. */
  gboolean    firmware_required;
  /* Checks whether @firmware runs on an MCU platform this driver speaks to. */
  gboolean  (*self_check) (const char *firmware);
  /* TRUE where the vendor checks the PSK before resetting the sensor and
   * reading its chip ID and OTP, so open does too. */
  gboolean    psk_checked_before_reset;
  /* TRUE where the first reset asks for the IRQ status reply. */
  gboolean    initial_reset_requests_irq;
  /* The preset slot holding the SHA-256 of the sensor's PSK. */
  guint32     psk_hash_type;
  /* FALSE where a failed PSK or production write could not be recovered
   * from, so the driver never writes one. */
  gboolean    provisionable;
  /* TRUE where an ACK that does not come in time is not an error for a
   * command that expects data: the wait moves on to the data, as the
   * vendor's _IoHubExec does. FALSE retries the command. */
  gboolean    ack_timeout_waits_for_data;
  /* Handshake attempts open and resume make before failing. */
  guint       channel_attempts;
  /* Handshake attempts a restart after a failed image read makes. */
  guint       channel_restart_attempts;
  /* Handshake attempts a reconnect the sensor asked for makes. */
  guint       channel_reconnect_attempts;
  /* TRUE where a D0 message from the sensor asks for a new secure-channel
   * session rather than carrying channel bytes. */
  gboolean    d0_requests_reconnect;
  /* TRUE where ACK flag 0x02, on any command, means the sensor lost its
   * configuration and needs it downloaded again. */
  gboolean    ack_reports_config_loss;
  /* TRUE where a reply in a shared response slot answers a command only if
   * its category and command are that command's, as the vendor's
   * IoHubNotifyDataIn checks; 53x5 native lets selectors alias. */
  gboolean    replies_match_command;
  /* TRUE where one undecodable image restarts the secure channel, as an
   * OpenSSL session is dead after a failed record; GTLS waits for a second. */
  gboolean    restart_on_first_image_error;

  /* Sets the ACK and data budgets, in ms, of the command with wire byte
   * @command. */
  void      (*command_budget) (guint8 command, guint *ack_ms, guint *response_ms);
  /* Requests the PSK hash; goodix_cmd_parse_psk_hash_reply() reads it. */
  void              (*read_psk_hash) (FpiSsm *ssm, FpDevice *dev);
  /* Returns a new SSM for one secure-channel handshake attempt. */
  FpiSsm           *(*new_channel_attempt) (FpDevice *dev);
  /* Returns the bytes to write for the protocol message @msg, or NULL when
   * the framing cannot carry it. */
  guint8           *(*frame) (const guint8 *msg, gsize msg_len, gsize *out_len);
  /* Returns the bytes to write for a raw TLS record, or NULL when the framing
   * cannot carry it; NULL on a variant without a TLS channel. */
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
