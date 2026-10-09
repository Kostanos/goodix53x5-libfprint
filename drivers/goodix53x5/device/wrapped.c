/*
 * Goodix 53x5 driver for libfprint — the wrapped variant (27c6:533c)
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

/* 533c is the GF5288 of the 53x5 parts behind a GM168SEC secure element: the
 * same commands and image pipeline, carried in the wrapped framing of the 51x7
 * family and secured with standard TLS 1.2-PSK, the sensor being the client. */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/transport.h"
#include "device/commands.h"
#include "device/session.h"

#include <string.h>

/* Wrapped framing: [flags(1)][length(2 LE)][sum of the first three(1)]
 * then length bytes. 0xa0 carries one protocol message, 0xb0 a TLS
 * handshake record, 0xb2 a 9-byte header and a TLS application record. */
#define GOODIX_PACK_HEADER       4
#define GOODIX_PACK_MESSAGE      0xa0
#define GOODIX_PACK_TLS          0xb0
#define GOODIX_PACK_TLS_DATA     0xb2
#define GOODIX_PACK_TLS_DATA_HDR 9

/* 533c ships with the all-zero PSK; this slot holds its SHA-256. */
#define GOODIX_WRAPPED_PSK_HASH_TYPE 0xbb020001
#define GOODIX_PSK_HASH_LEN          32

/* Returns the checksum a pack header carries in its fourth byte. */
static guint8
goodix_pack_checksum (const guint8 *header)
{
  return header[0] + header[1] + header[2];
}

static void
goodix_pack_write_header (guint8 *header, guint8 flags, gsize len)
{
  header[0] = flags;
  header[1] = len & 0xff;
  header[2] = (len >> 8) & 0xff;
  header[3] = goodix_pack_checksum (header);
}

/* Returns the payload length a pack header announces, or FALSE when its
 * checksum does not match. */
static gboolean
goodix_pack_read_header (const guint8 *header, gsize *len)
{
  if (goodix_pack_checksum (header) != header[3])
    return FALSE;
  *len = header[1] | (header[2] << 8);
  return TRUE;
}

/* Returns @data as one pack of kind @flags, zero-padded to whole 64-byte
 * writes. */
static guint8 *
goodix_frame_pack (guint8 flags, const guint8 *data, gsize data_len, gsize *out_len)
{
  gsize len = (GOODIX_PACK_HEADER + data_len + GOODIX_USB_CHUNK_SIZE - 1) /
              GOODIX_USB_CHUNK_SIZE * GOODIX_USB_CHUNK_SIZE;
  guint8 *framed = g_malloc0 (len);

  goodix_pack_write_header (framed, flags, data_len);
  memcpy (framed + GOODIX_PACK_HEADER, data, data_len);
  *out_len = len;
  return framed;
}

static guint8 *
goodix_frame_wrapped (const guint8 *msg, gsize msg_len, gsize *out_len)
{
  return goodix_frame_pack (GOODIX_PACK_MESSAGE, msg, msg_len, out_len);
}

static guint8 *
goodix_frame_tls_record (GBytes *record, gsize *out_len)
{
  gsize len;
  const guint8 *data = g_bytes_get_data (record, &len);

  return goodix_frame_pack (GOODIX_PACK_TLS, data, len, out_len);
}

/* Passes one protocol message to the receiver as the 64-byte direct-framing
 * cells it would have arrived in, so both framings share one parser. */
static void
goodix_rx_message (GoodixTransport *operation, const guint8 *msg, gsize len)
{
  guint8 cell[GOODIX_USB_CHUNK_SIZE];
  gsize offset = MIN (len, GOODIX_USB_CHUNK_SIZE);

  goodix_rx_cell (operation, msg, offset);
  while (offset < len)
    {
      gsize n = MIN (len - offset, GOODIX_USB_CHUNK_SIZE - 1);

      cell[0] = msg[0] | 1;
      memcpy (cell + 1, msg + offset, n);
      goodix_rx_cell (operation, cell, n + 1);
      offset += n;
    }
}

static void
goodix_rx_pack (FpiDeviceGoodix53x5 *self, GoodixTransport *operation,
                guint8 flags, const guint8 *payload, gsize len)
{
  switch (flags)
    {
    case GOODIX_PACK_MESSAGE:
      if (len)
        goodix_rx_message (operation, payload, len);
      break;

    case GOODIX_PACK_TLS:
      /* Handshake records share the category-D stream and its waiter. */
      goodix_mcu_publish (self, payload, len);
      break;

    case GOODIX_PACK_TLS_DATA:
      goodix_rx_image (operation, payload, len);
      break;

    default:
      fp_dbg ("Ignoring pack with flags 0x%02x, %zu bytes", flags, len);
      break;
    }
}

/* Dispatches every complete pack once @data is appended to the stream,
 * keeping a partial one for the next transfer; drops the stream at a bad
 * header. A pack never starts with zero, so its write padding is skipped. */
static void
goodix_receive_wrapped (FpiDeviceGoodix53x5 *self, GoodixTransport *operation,
                        const guint8 *data, gsize len)
{
  GByteArray *stream;

  if (!self->pack_rx)
    self->pack_rx = g_byte_array_new ();
  stream = self->pack_rx;
  g_byte_array_append (stream, data, len);

  for (;;)
    {
      gsize padding = 0, length;

      while (padding < stream->len && !stream->data[padding])
        padding++;
      g_byte_array_remove_range (stream, 0, padding);
      if (stream->len < GOODIX_PACK_HEADER)
        return;
      if (!goodix_pack_read_header (stream->data, &length))
        {
          fp_warn ("Dropping %u wrapped bytes with a bad pack header", stream->len);
          g_byte_array_set_size (stream, 0);
          return;
        }
      if (stream->len < GOODIX_PACK_HEADER + length)
        return;
      goodix_rx_pack (self, operation, stream->data[0],
                      stream->data + GOODIX_PACK_HEADER, length);
      g_byte_array_remove_range (stream, 0, GOODIX_PACK_HEADER + length);
    }
}

static GoodixFrameStatus
goodix_decrypt_frame_tls (FpiDeviceGoodix53x5 *self, const guint8 *payload,
                          gsize len, guint8 **out, gsize *out_len)
{
  gboolean established = self->tls && goodix_tls_established (self->tls);

  *out = established && len > GOODIX_PACK_TLS_DATA_HDR ?
         goodix_tls_decrypt (self->tls, payload + GOODIX_PACK_TLS_DATA_HDR,
                             len - GOODIX_PACK_TLS_DATA_HDR, out_len) : NULL;
  if (*out)
    return GOODIX_FRAME_DECRYPTED;
  return established ? GOODIX_FRAME_REJECTED_IN_SESSION : GOODIX_FRAME_REJECTED;
}

static void
goodix_read_psk_hash_wrapped (FpiSsm *ssm, FpDevice *dev)
{
  goodix_cmd_preset_read (ssm, dev, GOODIX_WRAPPED_PSK_HASH_TYPE, GOODIX_PSK_HASH_LEN);
}

typedef enum {
  GOODIX_TLS_REQUEST,
  GOODIX_TLS_RECV,
  GOODIX_TLS_STEP,
  GOODIX_TLS_SENT,
  GOODIX_TLS_ESTABLISHED,
  GOODIX_TLS_NUM_STATES,
} GoodixTlsState;

/* Runs one TLS handshake attempt, the sensor being the client; fails when it
 * sends a record OpenSSL rejects or a reply takes over 2 s. */
static void
goodix_tls_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  g_autoptr(GError) error = NULL;

  if (g_cancellable_set_error_if_cancelled (goodix_session_io_cancellable (dev), &error))
    {
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }

  switch ((GoodixTlsState) fpi_ssm_get_cur_state (ssm))
    {
    case GOODIX_TLS_REQUEST:
      goodix_transport_reset_mcu (dev);
      g_clear_pointer (&self->tls, goodix_tls_free);
      self->tls = goodix_tls_new (self->psk, GOODIX_PSK_LEN, &error);
      if (!self->tls)
        {
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
          return;
        }
      goodix_cmd_tls_request (ssm, dev);
      break;

    case GOODIX_TLS_RECV:
      goodix_recv_mcu (ssm, dev, GOODIX_CHANNEL_REPLY_TIMEOUT_MS, 0);
      break;

    case GOODIX_TLS_STEP:
      {
        g_autoptr(GBytes) out = NULL;
        const guint8 *in = NULL;
        gsize in_len = 0;

        if (self->mcu_reply)
          in = g_bytes_get_data (self->mcu_reply, &in_len);
        if (!goodix_tls_handshake (self->tls, in, in_len, &out, &error))
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
        else if (out)
          goodix_cmd_send_tls_record (ssm, dev, out);
        else
          fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_TLS_SENT:
      fpi_ssm_jump_to_state (ssm, goodix_tls_established (self->tls) ?
                             GOODIX_TLS_ESTABLISHED : GOODIX_TLS_RECV);
      break;

    case GOODIX_TLS_ESTABLISHED:
      goodix_cmd_tls_established (ssm, dev);
      break;

    case GOODIX_TLS_NUM_STATES:
      g_assert_not_reached ();
    }
}

static FpiSsm *
goodix_tls_attempt_new (FpDevice *dev)
{
  return fpi_ssm_new (dev, goodix_tls_ssm_handler, GOODIX_TLS_NUM_STATES);
}

const GoodixVariant goodix_variant_wrapped = {
  .channel_name = "TLS",
  .usb_interface = 0,
  .ep_in = 0x03 | FPI_USB_ENDPOINT_IN,
  .ep_out = 0x01 | FPI_USB_ENDPOINT_OUT,
  .chip_id_request_len = 4,
  .psk_hash_type = GOODIX_WRAPPED_PSK_HASH_TYPE,
  /* 533c returns no firmware in APP mode, so nothing could restore it. */
  .provisionable = FALSE,
  .reply_implies_ack = TRUE,
  .channel_restart_disarms = TRUE,
  .read_psk_hash = goodix_read_psk_hash_wrapped,
  .new_channel_attempt = goodix_tls_attempt_new,
  .frame = goodix_frame_wrapped,
  .frame_record = goodix_frame_tls_record,
  .receive = goodix_receive_wrapped,
  .decrypt_frame = goodix_decrypt_frame_tls,
};
