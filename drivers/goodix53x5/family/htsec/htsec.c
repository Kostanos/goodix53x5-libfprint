/*
 * Goodix 53x5 driver for libfprint — the HTSEC family (5335/5385/5395)
 * Copyright (C) 2024 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/transport.h"
#include "device/commands.h"
#include "family/htsec/htsec.h"

#include <string.h>

/* USB endpoints — interface 1, CDC Data class */
#define GOODIX_EP_OUT (0x03 | FPI_USB_ENDPOINT_OUT)
#define GOODIX_EP_IN  (0x01 | FPI_USB_ENDPOINT_IN)

/* The 53x5 native budgets: the command table, with fixed fallbacks for
 * commands it does not list. */
static void
goodix_htsec_command_budget (guint8 command, guint *ack_ms, guint *response_ms)
{
  const GoodixCommandPolicy *policy = goodix_cmd_policy (command);

  *ack_ms = policy ? policy->ack_ms : GOODIX_ACK_TIMEOUT;
  *response_ms = policy && policy->response_ms ? policy->response_ms : GOODIX_DATA_TIMEOUT;
}

/* Returns @msg split into 64-byte writes. Continuation chunks prepend the
 * command byte | 1 and carry up to 63 more bytes of message data. */
static guint8 *
goodix_frame_direct (const guint8 *msg, gsize msg_len, gsize *out_len)
{
  gsize first_len = MIN (msg_len, GOODIX_USB_CHUNK_SIZE);
  gsize total_chunks = 1 + (msg_len - first_len + 62) / 63;
  gsize padded_len = total_chunks * GOODIX_USB_CHUNK_SIZE;
  guint8 *chunked = g_malloc0 (padded_len);
  gsize src_offset = first_len;

  memcpy (chunked, msg, first_len);
  for (gsize dst_offset = GOODIX_USB_CHUNK_SIZE;
       dst_offset < padded_len; dst_offset += GOODIX_USB_CHUNK_SIZE)
    {
      gsize data_in_chunk = MIN (63, msg_len - src_offset);

      chunked[dst_offset] = msg[0] | 1;
      memcpy (chunked + dst_offset + 1, msg + src_offset, data_in_chunk);
      src_offset += data_in_chunk;
    }

  *out_len = padded_len;
  return chunked;
}

/* Native posts one 0x8000-byte read and traverses that capacity in 64-byte
 * cells, gated by nonzero received length and first byte. Only transferred
 * bytes are available here; never parse the unfilled allocation suffix. */
static void
goodix_receive_direct (FpiDeviceGoodix53x5 *self, GoodixTransport *operation,
                       const guint8 *data, gsize len)
{
  if (len && data[0])
    for (gsize offset = 0; offset < len; offset += GOODIX_USB_CHUNK_SIZE)
      goodix_rx_cell (operation, data + offset, MIN (GOODIX_USB_CHUNK_SIZE, len - offset));
}

/* 53x5 native checks no MCU platform. */
static gboolean
goodix_direct_self_check (const char *firmware)
{
  (void) firmware;
  return TRUE;
}

static void
goodix_read_psk_hash_direct (FpiSsm *ssm, FpDevice *dev)
{
  goodix_cmd_production_read (ssm, dev, goodix_family_htsec.psk_hash_type);
}

const GoodixFamily goodix_family_htsec = {
  .link = {
    .usb_interface = 1,
    .ep_in = GOODIX_EP_IN,
    .ep_out = GOODIX_EP_OUT,
    .frame = goodix_frame_direct,
    .frame_record = NULL,
    .receive = goodix_receive_direct,
  },
  .protocol = {
    .wake_payload_len = 2,
    .ec_on_payload = { 0x01, 0x01, 0x00 },
    .command_budget = goodix_htsec_command_budget,
    .ack_timeout_waits_for_data = FALSE,
    .ack_reports_config_loss = FALSE,
    .d0_requests_reconnect = FALSE,
    .replies_match_command = FALSE,
    .provisionable = TRUE,
  },
  .channel = {
    .name = "GTLS",
    /* deviceInit runs the three-attempt wrapper twice; the event restart once. */
    .attempts = { .open = 6, .after_failed_read = 3, .reconnect = 3 },
    .attempt_new = goodix_gtls_attempt_new,
    .decrypt_frame = goodix_decrypt_frame_gtls,
    .restart_on_first_image_error = FALSE,
    .restart_disarms = FALSE,
  },
  .firmware_reads = 5,
  .firmware_required = FALSE,
  .self_check = goodix_direct_self_check,
  .psk_checked_before_reset = FALSE,
  .initial_reset_requests_irq = FALSE,
  .psk_hash_type = 0xB003,
  .read_psk_hash = goodix_read_psk_hash_direct,
};
