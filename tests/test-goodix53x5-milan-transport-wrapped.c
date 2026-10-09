/*
 * Goodix 533c wrapped framing and TLS channel contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <openssl/ssl.h>

static FpDevice *
wrapped_device_new (void)
{
  FpDevice *dev = fixture_device_new_variant (GOODIX_VARIANT_WRAPPED);

  g_assert_true (goodix_variant (FPI_DEVICE_GOODIX53X5 (dev)) == &goodix_variant_wrapped);
  return dev;
}

/* A wrapped pack header reads back what it was written with, matches the
 * vendor driver's bytes, and is refused once its checksum is wrong. */
static void
test_wrapped_pack_header (void)
{
  const guint8 vendor[GOODIX_PACK_HEADER] = { 0xa0, 0x14, 0x00, 0xb4 };
  const guint8 msg[70] = { 0xa8, 0x03, 0x00 };
  guint8 header[GOODIX_PACK_HEADER];
  gsize framed_len, len;
  g_autofree guint8 *framed = goodix_frame_wrapped (msg, sizeof (msg), &framed_len);

  goodix_pack_write_header (header, GOODIX_PACK_MESSAGE, 0x14);
  g_assert_cmpmem (header, sizeof (header), vendor, sizeof (vendor));

  g_assert_cmpuint (framed_len, ==, 2 * GOODIX_USB_CHUNK_SIZE);
  g_assert_cmpuint (framed[0], ==, GOODIX_PACK_MESSAGE);
  g_assert_true (goodix_pack_read_header (framed, &len));
  g_assert_cmpmem (framed + GOODIX_PACK_HEADER, len, msg, sizeof (msg));

  framed[3]++;
  g_assert_false (goodix_pack_read_header (framed, &len));
}

/* Only the vendor's 0xa and 0xb families with a possible length are headers. */
static void
test_wrapped_pack_header_rejects (void)
{
  guint8 header[GOODIX_PACK_HEADER];
  gsize len;

  goodix_pack_write_header (header, 0xb2, GOODIX_PACK_MAX_PAYLOAD);
  g_assert_true (goodix_pack_read_header (header, &len));
  g_assert_cmpuint (len, ==, GOODIX_PACK_MAX_PAYLOAD);

  goodix_pack_write_header (header, 0xb2, GOODIX_PACK_MAX_PAYLOAD + 1);
  g_assert_false (goodix_pack_read_header (header, &len));
  goodix_pack_write_header (header, 0xc0, 4);
  g_assert_false (goodix_pack_read_header (header, &len));
  goodix_pack_write_header (header, 0x90, 4);
  g_assert_false (goodix_pack_read_header (header, &len));
}

/* A misread header whose checksum happens to pass must not hold the stream
 * waiting for a pack that never comes. */
static void
test_wrapped_bad_header_drops_stream (void)
{
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixTransport idle = { .dev = dev };
  guint8 data[GOODIX_PACK_HEADER + 8] = { 0 };

  goodix_pack_write_header (data, 0xb0, 0xffff);
  data[GOODIX_PACK_HEADER] = 0x17;
  /* wrapped.c is compiled into this suite, under its log domain. */
  g_test_expect_message ("libfprint", G_LOG_LEVEL_WARNING,
                         "Dropping * wrapped bytes with a bad pack header");
  goodix_receive_wrapped (self, &idle, data, sizeof (data));
  g_test_assert_expected_messages ();
  g_assert_cmpuint (self->pack_rx->len, ==, 0);
  g_clear_object (&action_cancel_token);
}

/* A failed read loses bytes of the stream, so a partial pack must go too. */
static void
test_wrapped_reader_error_drops_stream (void)
{
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixTransport idle = { .dev = dev };
  GoodixReader *reader = g_new0 (GoodixReader, 1);
  guint8 partial[GOODIX_PACK_HEADER + 2] = { 0 };

  goodix_pack_write_header (partial, 0xa0, 16);
  goodix_receive_wrapped (self, &idle, partial, sizeof (partial));
  g_assert_cmpuint (self->pack_rx->len, ==, sizeof (partial));

  reader->dev = dev;
  reader->pending = TRUE;
  self->reader = reader;
  goodix_rx_cb (NULL, dev, reader,
                g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO, "Lost"));
  g_assert_cmpuint (self->pack_rx->len, ==, 0);

  self->reader = NULL;
  g_clear_error (&reader->error);
  g_free (reader);
  g_clear_object (&action_cancel_token);
}

static void
record_state (FpiSsm *ssm, FpDevice *dev)
{
  *(int *) fpi_ssm_get_data (ssm) = fpi_ssm_get_cur_state (ssm);
}

static int
restarted_next_state (gboolean stop_requested)
{
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  GoodixScanCoordinatorData data = { .stop_requested = stop_requested };
  int state = -1;

  data.ssm = fpi_ssm_new (dev, record_state, GOODIX_SCAN_COORD_NUM_STATES);
  fpi_ssm_set_data (data.ssm, &state, NULL);
  fpi_ssm_start (data.ssm, NULL);
  goodix_scan_gtls_restarted (dev, NULL, &data);
  fpi_ssm_free (data.ssm);
  g_clear_object (&action_cancel_token);
  return state;
}

/* After a 533c channel restart the scan arms again, unless it was stopped
 * meanwhile: then it takes the ordinary path, which ends the scan. */
static void
test_wrapped_restart_rearm_yields_to_stop (void)
{
  g_assert_cmpint (restarted_next_state (FALSE), ==, GOODIX_SCAN_COORD_CHANNEL_REARM);
  g_assert_cmpint (restarted_next_state (TRUE), ==, GOODIX_SCAN_COORD_WAIT_EVENT);
}

static unsigned int
client_psk (SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len,
            unsigned char *psk, unsigned int max_psk_len)
{
  g_strlcpy (identity, "Client_identity", max_identity_len);
  memset (psk, 0, GOODIX_PSK_LEN);
  return GOODIX_PSK_LEN;
}

/* Returns and clears everything written to @bio. */
static GBytes *
take_bio (BIO *bio)
{
  char *data;
  long len = BIO_get_mem_data (bio, &data);
  GBytes *bytes = g_bytes_new (data, MAX (len, 0));

  (void) BIO_reset (bio);
  return bytes;
}

/* An in-memory TLS client in the sensor's role, connected to one GoodixTls. */
typedef struct
{
  SSL_CTX *ctx;
  SSL     *ssl;
  BIO     *in;
  BIO     *out;
} TlsPeer;

static TlsPeer *
tls_peer_connect (GoodixTls *tls)
{
  TlsPeer *peer = g_new0 (TlsPeer, 1);
  g_autoptr(GBytes) to_server = NULL;

  peer->ctx = SSL_CTX_new (TLS_client_method ());
  SSL_CTX_set_max_proto_version (peer->ctx, TLS1_2_VERSION);
  SSL_CTX_set_cipher_list (peer->ctx, "PSK-AES128-CBC-SHA256");
  SSL_CTX_set_psk_client_callback (peer->ctx, client_psk);
  peer->ssl = SSL_new (peer->ctx);
  peer->in = BIO_new (BIO_s_mem ());
  peer->out = BIO_new (BIO_s_mem ());
  BIO_set_mem_eof_return (peer->in, -1);
  SSL_set_bio (peer->ssl, peer->in, peer->out);
  SSL_set_connect_state (peer->ssl);

  while (!goodix_tls_established (tls) || SSL_do_handshake (peer->ssl) != 1)
    {
      g_autoptr(GBytes) to_client = NULL;
      g_autoptr(GError) error = NULL;
      gsize len;
      const guint8 *data;

      SSL_do_handshake (peer->ssl);
      g_clear_pointer (&to_server, g_bytes_unref);
      to_server = take_bio (peer->out);
      data = g_bytes_get_data (to_server, &len);
      g_assert_true (goodix_tls_handshake (tls, data, len, &to_client, &error));
      if (to_client)
        BIO_write (peer->in, g_bytes_get_data (to_client, NULL),
                   g_bytes_get_size (to_client));
    }
  return peer;
}

/* Returns the peer of a TLS session established on @self, as after open. */
static TlsPeer *
tls_session_establish (FpiDeviceGoodix53x5 *self)
{
  self->tls = goodix_tls_new (self->psk, GOODIX_PSK_LEN, NULL);
  return tls_peer_connect (self->tls);
}

/* Returns @data sealed into one record by @peer. */
static GBytes *
tls_peer_seal (TlsPeer *peer, const void *data, gsize len)
{
  g_assert_cmpint (SSL_write (peer->ssl, data, len), ==, len);
  return take_bio (peer->out);
}

static void
tls_peer_free (TlsPeer *peer)
{
  SSL_free (peer->ssl);
  SSL_CTX_free (peer->ctx);
  g_free (peer);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (TlsPeer, tls_peer_free)

/* A record cut short fails at once instead of corrupting the next one. */
static void
test_wrapped_tls_truncated_record (void)
{
  const guint8 psk[GOODIX_PSK_LEN] = { 0 };
  const char image[] = "image bytes";
  GoodixTls *tls = goodix_tls_new (psk, sizeof (psk), NULL);
  g_autoptr(TlsPeer) peer = tls_peer_connect (tls);
  g_autoptr(GBytes) cut = tls_peer_seal (peer, image, sizeof (image));
  g_autofree guint8 *plain = NULL;
  gsize len, plain_len = 0;
  const guint8 *data = g_bytes_get_data (cut, &len);

  g_test_expect_message ("libfprint-goodix53x5", G_LOG_LEVEL_WARNING,
                         "TLS record is incomplete");
  g_assert_null (goodix_tls_decrypt (tls, data, len - 1, &plain_len));
  g_test_assert_expected_messages ();
  goodix_tls_free (tls);
  g_clear_pointer (&peer, tls_peer_free);

  tls = goodix_tls_new (psk, sizeof (psk), NULL);
  peer = tls_peer_connect (tls);
  g_autoptr(GBytes) whole = tls_peer_seal (peer, image, sizeof (image));
  data = g_bytes_get_data (whole, &len);
  plain = goodix_tls_decrypt (tls, data, len, &plain_len);
  g_assert_cmpmem (plain, plain_len, image, sizeof (image));
  goodix_tls_free (tls);
}

/* A sensor that never finishes the handshake fails it after ten calls, as
 * McuStartTls does. */
static void
test_wrapped_tls_handshake_limit (void)
{
  const guint8 psk[GOODIX_PSK_LEN] = { 0 };
  GoodixTls *tls = goodix_tls_new (psk, sizeof (psk), NULL);
  g_autoptr(GError) error = NULL;

  for (guint i = 0; i < 10; i++)
    {
      g_autoptr(GBytes) out = NULL;

      g_assert_true (goodix_tls_handshake (tls, NULL, 0, &out, &error));
      g_assert_null (out);
    }
  g_autoptr(GBytes) out = NULL;
  g_assert_false (goodix_tls_handshake (tls, NULL, 0, &out, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
  goodix_tls_free (tls);
}

/* Returns an image pack payload: the 9-byte prefix and @image sealed by
 * @peer. */
static GByteArray *
image_payload (TlsPeer *peer, const guint8 *image, gsize len)
{
  GByteArray *payload = g_byte_array_new ();
  const guint8 prefix[GOODIX_PACK_TLS_DATA_HDR] = { 0 };
  g_autoptr(GBytes) record = tls_peer_seal (peer, image, len);

  g_byte_array_append (payload, prefix, sizeof (prefix));
  g_byte_array_append (payload, g_bytes_get_data (record, NULL), g_bytes_get_size (record));
  return payload;
}

/* Returns a raw12 image of @len bytes whose last four carry the CRC of the
 * pixels before them, in the sensor's byte order. */
static guint8 *
image_with_crc (gsize len)
{
  guint8 *image = g_malloc0 (len);
  guint32 crc = goodix_crypto_crc32_mpeg2 (image, len - 4);

  image[len - 4] = (crc >> 8) & 0xff;
  image[len - 3] = crc & 0xff;
  image[len - 2] = crc >> 24;
  image[len - 1] = (crc >> 16) & 0xff;
  return image;
}

/* Only a decrypted image of exactly the raw12 size with a matching CRC is
 * an image, as in FpParseImage; anything else counts against the session. */
static void
test_wrapped_image_check (void)
{
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  g_autoptr(TlsPeer) peer = NULL;
  g_autofree guint8 *image = image_with_crc (GOODIX_WRAPPED_IMAGE_LEN);
  g_autofree guint8 *longer = image_with_crc (GOODIX_WRAPPED_IMAGE_LEN + 2);
  g_autoptr(GByteArray) good = NULL;
  g_autoptr(GByteArray) bad_crc = NULL;
  g_autoptr(GByteArray) bad_len = NULL;
  g_autofree guint8 *out = NULL;
  gsize out_len = 0;

  peer = tls_session_establish (self);
  good = image_payload (peer, image, GOODIX_WRAPPED_IMAGE_LEN);
  image[0] ^= 1;
  bad_crc = image_payload (peer, image, GOODIX_WRAPPED_IMAGE_LEN);
  bad_len = image_payload (peer, longer, GOODIX_WRAPPED_IMAGE_LEN + 2);

  g_assert_cmpint (goodix_decrypt_frame_tls (self, good->data, good->len, &out, &out_len),
                   ==, GOODIX_FRAME_DECRYPTED);
  g_assert_cmpuint (out_len, ==, GOODIX_WRAPPED_IMAGE_LEN);
  g_clear_pointer (&out, g_free);
  for (guint i = 0; i < 2; i++)
    {
      GByteArray *payload = i ? bad_len : bad_crc;

      g_test_expect_message ("libfprint", G_LOG_LEVEL_WARNING,
                             "Rejecting a * image without a valid CRC");
      g_assert_cmpint (goodix_decrypt_frame_tls (self, payload->data, payload->len,
                                                 &out, &out_len),
                       ==, GOODIX_FRAME_REJECTED_IN_SESSION);
      g_test_assert_expected_messages ();
      g_assert_null (out);
    }
  g_clear_object (&action_cancel_token);
}

/* One rejected image restarts a 533c channel: OpenSSL fails every record
 * after a bad one, so waiting for a second would lose that image too. */
static void
test_wrapped_first_image_error_restarts (void)
{
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixTransport idle = { .dev = dev };
  g_autoptr(TlsPeer) peer = NULL;
  g_autofree guint8 *image = image_with_crc (GOODIX_WRAPPED_IMAGE_LEN);
  g_autoptr(GByteArray) bad = NULL;

  peer = tls_session_establish (self);
  image[0] ^= 1;
  bad = image_payload (peer, image, GOODIX_WRAPPED_IMAGE_LEN);

  g_test_expect_message ("libfprint", G_LOG_LEVEL_WARNING, "Rejecting a * image*");
  g_assert_false (goodix_rx_image (&idle, bad->data, bad->len));
  g_test_assert_expected_messages ();
  g_assert_true (self->image_response_failed);
  g_assert_true (self->gtls_restart_pending);
  g_clear_object (&action_cancel_token);
}

/* How the simulated 533c answers the open sequence. */
typedef struct
{
  const char *firmware;
  /* Firmware-version reads that time out before one is answered. */
  guint       silent_firmware_reads;
  gboolean    foreign_psk;
  /* The firmware read gets its reply but never its ACK. */
  gboolean    unacked_firmware;
} WrappedOpen;

/* Answers the read pending for io.command: its ACK first, then its reply. */
static void
wrapped_open_answer (const WrappedOpen *sensor, gboolean *acked, guint *firmware_reads)
{
  static const guint8 chip[4] = { 0x0c, 0xa1, 0x00, 0x22 };
  static const guint8 irq[4] = { 0 };
  /* Status, slot 0xbb020001, length 32, SHA-256 of the all-zero PSK. */
  guint8 psk_hash[41] = {
    0, 0x01, 0x00, 0x02, 0xbb, 32, 0, 0, 0,
    0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b,
    0x8e, 0x9f, 0x8e, 0x20, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3,
    0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25,
  };

  if (io.command == 0xa8 && *firmware_reads < sensor->silent_firmware_reads)
    {
      (*firmware_reads)++;
      fixture_complete (g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                             "Silent firmware read"));
      return;
    }
  if (!*acked && io.command == 0xa8 && sensor->unacked_firmware)
    {
      *acked = TRUE;
      fixture_complete (g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                             "No ACK"));
      return;
    }
  if (!*acked)
    {
      ack_reply (usb.pending, io.command);
      *acked = TRUE;
    }
  else if (io.command == 0xa8)
    reply (usb.pending, 0xa, 4, (const guint8 *) sensor->firmware, strlen (sensor->firmware) + 1);
  else if (io.command == 0xe4)
    {
      psk_hash[20] ^= sensor->foreign_psk;
      reply (usb.pending, 0xe, 2, psk_hash, sizeof (psk_hash));
    }
  else if (io.command == 0xa2)
    reply (usb.pending, 0xa, 1, irq, sizeof (irq));
  else if (io.command == 0x82)
    reply (usb.pending, 0x8, 1, chip, sizeof (chip));
  fixture_complete (NULL);
}

/* Prepares @dev to run commands against the fixture's simulated USB. */
static void
command_session_begin (FpDevice *dev)
{
  static const Scenario scenario = { .schedule = EVENT_CANCELLED };

  memset (&io, 0, sizeof (io));
  io.scenario = &scenario;
  FPI_DEVICE_GOODIX53X5 (dev)->cancel = g_cancellable_new ();
}

/* Joins @dev's reader and releases what command_session_begin() and the
 * commands left behind. */
static void
command_session_end (FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  fixture_join_reader (dev);
  g_clear_object (&self->cancel);
  g_clear_pointer (&self->rx.buf, g_free);
  g_clear_object (&action_cancel_token);
}

/* Runs open on a 533c up to its OTP read and returns the commands it wrote,
 * as "cmd(payload length:first payload byte)," each, with its error in
 * @error. */
static gchar *
run_wrapped_open (const WrappedOpen *sensor, GError **error)
{
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  gboolean acked = FALSE;
  guint firmware_reads = 0;

  command_session_begin (dev);
  startup_trace = g_string_new (NULL);
  fpi_ssm_start (fpi_ssm_new_full (dev, goodix_open_ssm_handler,
                                  GOODIX_OPEN_READ_OTP, GOODIX_OPEN_READ_OTP,
                                  "wrapped-open"), startup_done);
  for (guint step = 0; !io.completions && step < 200; step++)
    {
      if (!self->transport)
        g_main_context_iteration (NULL, TRUE);
      else if (usb.pending->endpoint == goodix_variant_wrapped.ep_out)
        {
          /* The message's LE16 length counts its payload and checksum. */
          g_string_append_printf (startup_trace, "(%u:%02x),", usb.pending->buffer[5] - 1,
                                  usb.pending->buffer[7]);
          acked = FALSE;
          fixture_complete (NULL);
        }
      else
        wrapped_open_answer (sensor, &acked, &firmware_reads);
    }
  if (!io.completions)
    g_error ("open did not finish: %s", startup_trace->str);
  *error = g_steal_pointer (&io.error);
  command_session_end (dev);
  return g_string_free (g_steal_pointer (&startup_trace), FALSE);
}

/* 533c opens in the vendor's order: wake with a four-byte NOP, read the
 * firmware for SelfCheck, check the PSK, then reset asking for the IRQ
 * reply and read the chip ID with the five-byte request. */
static void
test_wrapped_open_order (void)
{
  const WrappedOpen sensor = { .firmware = "GF5288_GM168SEC_APP_13016" };
  g_autoptr(GError) error = NULL;
  g_autofree gchar *trace = run_wrapped_open (&sensor, &error);

  g_assert_no_error (error);
  g_assert_cmpstr (trace, ==, "00,(4:00),a8,(2:00),e4,(16:20),a2,(2:05),82,(5:00),");
}

/* A missing ACK only costs its wait: the firmware reply that follows still
 * completes the read, which is not sent again. */
static void
test_wrapped_open_unacked_reply (void)
{
  const WrappedOpen sensor = { .firmware = "GF5288_GM168SEC_APP_13016",
                               .unacked_firmware = TRUE };
  g_autoptr(GError) error = NULL;
  g_autofree gchar *trace = run_wrapped_open (&sensor, &error);

  g_assert_no_error (error);
  g_assert_cmpstr (trace, ==, "00,(4:00),a8,(2:00),e4,(16:20),a2,(2:05),82,(5:00),");
}

/* SelfCheck refuses firmware for another MCU before anything else runs. */
static void
test_wrapped_open_foreign_firmware (void)
{
  const WrappedOpen sensor = { .firmware = "GF5288_GD32_APP_13016" };
  g_autoptr(GError) error = NULL;
  g_autofree gchar *trace = run_wrapped_open (&sensor, &error);

  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  g_assert_cmpstr (trace, ==, "00,(4:00),a8,(2:00),");
}

/* Without a firmware version there is no SelfCheck, so open stops; 53x5
 * native continues instead. */
static void
test_wrapped_open_unreadable_firmware (void)
{
  const WrappedOpen sensor = { .firmware = "GF5288_GM168SEC_APP_13016",
                               .silent_firmware_reads = G_MAXUINT };
  g_autoptr(GError) error = NULL;
  g_autofree gchar *trace = run_wrapped_open (&sensor, &error);

  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
  g_assert_nonnull (strstr (error->message, "Firmware version unreadable"));
  g_assert_false (strstr (trace, "e4"));
}

/* A sensor holding another PSK stops open before the reset. */
static void
test_wrapped_open_foreign_psk (void)
{
  const WrappedOpen sensor = { .firmware = "GF5288_GM168SEC_APP_13016",
                               .foreign_psk = TRUE };
  g_autoptr(GError) error = NULL;
  g_autofree gchar *trace = run_wrapped_open (&sensor, &error);

  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_assert_cmpstr (trace, ==, "00,(4:00),a8,(2:00),e4,(16:20),");
}

/* The guard blocks every way the vendor driver writes a 533c (the PSK write
 * as e0 and as its e4 fallback, firmware write, APP erase) and nothing that
 * only reads it. Direct sensors, which the driver provisions, pass. */
static void
test_wrapped_write_guard (void)
{
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  g_autoptr(FpDevice) direct = NULL;
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  /* Length 32, offset 0, slot 0xbb020001, zero word. */
  guint8 preset_read[16] = { 32, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x02, 0xbb };
  /* Total, fragment length and offset, then the PSK writer's prefix. */
  guint8 psk_write[22] = { 22, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0,
                           0x56, 0xa5, 0xbb, 0x95, 0x6b, 0x7c, 0x8d, 0x9e };
  guint8 last_fragment[16] = { 0x04, 0x01, 0, 0, 4, 0, 0, 0, 0, 1, 0, 0 };
  guint8 two[2] = { 0 };
  const struct { guint8 category, command; guint8 *payload; gsize len; gboolean refused; } cases[] = {
    { 0xe, 0x2, preset_read, sizeof (preset_read), FALSE },
    { 0xa, 0x4, two, sizeof (two), FALSE },
    { 0xa, 0x1, two, sizeof (two), FALSE },
    { 0xe, 0x0, psk_write, sizeof (psk_write), TRUE },
    { 0xe, 0x2, psk_write, sizeof (psk_write), TRUE },
    { 0xe, 0x2, last_fragment, sizeof (last_fragment), TRUE },
    { 0xe, 0x1, two, sizeof (two), TRUE },
    { 0xf, 0x0, two, sizeof (two), TRUE },
    { 0xa, 0x2, two, sizeof (two), TRUE },
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      GoodixCmd cmd = { .category = cases[i].category, .command = cases[i].command,
                        .payload = cases[i].payload, .payload_len = cases[i].len };

      g_assert_cmpint (goodix_cmd_refused (self, &cmd), ==, cases[i].refused);
    }
  g_clear_object (&action_cancel_token);

  direct = fixture_device_new ();
  {
    GoodixCmd write = { .category = 0xe, .command = 0x1, .payload = two, .payload_len = 2 };

    g_assert_false (goodix_cmd_refused (FPI_DEVICE_GOODIX53X5 (direct), &write));
  }
  g_clear_object (&action_cancel_token);
}

/* Feeds @dev one protocol message as the sensor frames it. */
static void
receive_message (FpDevice *dev, guint8 category, guint8 command,
                 const guint8 *payload, gsize len)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixTransport idle = { .dev = dev };
  gsize message_len, framed_len;
  g_autofree guint8 *message = goodix_proto_build_message (category, command, payload, len,
                                                           TRUE, &message_len);
  g_autofree guint8 *framed = fixture_wrap (message, message_len, &framed_len);

  if (fixture_wrapped (dev))
    goodix_receive_wrapped (self, &idle, framed, framed_len);
  else
    for (gsize offset = 0; offset < message_len; offset += GOODIX_USB_CHUNK_SIZE)
      goodix_rx_cell (&idle, message + offset, MIN (GOODIX_USB_CHUNK_SIZE, message_len - offset));
}

/* On 533c an ACK with flag 0x02, for any command, reports lost configuration
 * until a configuration reply arrives; 53x5 ACKs never report it. */
static void
test_wrapped_ack_reports_config_loss (void)
{
  const guint8 lost[2] = { 0xa8, 0x03 };
  const guint8 config_reply[1] = { 1 };
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  g_autoptr(FpDevice) direct = NULL;
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  receive_message (dev, 0xb, 0, lost, sizeof (lost));
  g_assert_true (self->config_lost);
  receive_message (dev, 0x9, 0, config_reply, sizeof (config_reply));
  g_assert_false (self->config_lost);
  g_clear_object (&action_cancel_token);

  direct = fixture_device_new ();
  receive_message (direct, 0xb, 0, lost, sizeof (lost));
  g_assert_false (FPI_DEVICE_GOODIX53X5 (direct)->config_lost);
  g_clear_object (&action_cancel_token);
}

/* Returns the ACK and data budgets @dev gives the command with wire byte
 * @command. */
static void
command_budget (FpDevice *dev, guint8 command, guint *ack_ms, guint *response_ms)
{
  GoodixTransport operation = { .dev = dev, .cmd = { .category = command >> 4,
                                                     .command = (command >> 1) & 7 } };

  goodix_cmd_set_policy (&operation);
  *ack_ms = operation.ack_timeout_ms;
  *response_ms = operation.response_timeout_ms;
}

/* 533c commands get the vendor's 1500 ms waits, with 500 ms for the EC
 * control ACK; 53x5 keeps its native table. */
static void
test_wrapped_command_budgets (void)
{
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  g_autoptr(FpDevice) direct = NULL;
  guint ack, response;

  command_budget (dev, 0x32, &ack, &response);
  g_assert_cmpuint (ack, ==, 1500);
  g_assert_cmpuint (response, ==, 1500);
  command_budget (dev, 0x20, &ack, &response);
  g_assert_cmpuint (response, ==, 1500);
  command_budget (dev, 0xae, &ack, &response);
  g_assert_cmpuint (ack, ==, 500);
  g_clear_object (&action_cancel_token);

  direct = fixture_device_new ();
  command_budget (direct, 0x32, &ack, &response);
  g_assert_cmpuint (ack, ==, 500);
  command_budget (direct, 0x20, &ack, &response);
  g_assert_cmpuint (response, ==, 500);
  g_clear_object (&action_cancel_token);
}

/* A D0 message from a 533c asks for a new TLS session: it requests a channel
 * restart that arms finger-down, and is not taken as channel bytes. On 53x5
 * the same message is GTLS channel data. */
static void
test_wrapped_d0_requests_reconnect (void)
{
  const guint8 d0[2] = { 0 };
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  g_autoptr(FpDevice) direct = NULL;
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);

  receive_message (dev, 0xd, 0, d0, sizeof (d0));
  g_assert_true (self->reconnect_requested);
  g_assert_true (self->gtls_restart_pending);
  g_assert_true (!self->mcu_rx || self->mcu_rx->len == 0);
  g_clear_object (&action_cancel_token);

  direct = fixture_device_new ();
  receive_message (direct, 0xd, 0, d0, sizeof (d0));
  g_assert_false (FPI_DEVICE_GOODIX53X5 (direct)->reconnect_requested);
  g_assert_false (FPI_DEVICE_GOODIX53X5 (direct)->gtls_restart_pending);
  g_assert_cmpuint (FPI_DEVICE_GOODIX53X5 (direct)->mcu_rx->len, ==, sizeof (d0));
  g_clear_object (&action_cancel_token);
}

static void
ec_on_handler (FpiSsm *ssm, FpDevice *dev)
{
  goodix_cmd_ec_control (ssm, dev, TRUE);
}

/* Returns the payload @dev writes to turn power-button isolation on. */
static GBytes *
ec_on_payload (FpDevice *dev)
{
  const guint8 *message;
  GBytes *payload;

  command_session_begin (dev);
  fpi_ssm_start (fpi_ssm_new (dev, ec_on_handler, 1), startup_done);
  g_assert_nonnull (usb.pending);
  message = usb.pending->buffer + (fixture_wrapped (dev) ? 4 : 0);
  g_assert_cmpuint (message[0], ==, 0xae);
  payload = g_bytes_new (message + 3, 3);
  fixture_complete (NULL);
  ack_reply (usb.pending, 0xae);
  fixture_complete (NULL);
  g_assert_cmpuint (io.completions, ==, 1);
  g_assert_no_error (io.error);
  command_session_end (dev);
  return payload;
}

/* 533c isolates the power button with [enable, mode 0, enable], the layout
 * McuSetEcCtrl builds; 53x5 keeps its native bytes. */
static void
test_wrapped_ec_on_payload (void)
{
  const guint8 wrapped[3] = { 0x01, 0x00, 0x01 };
  const guint8 direct[3] = { 0x01, 0x01, 0x00 };
  g_autoptr(FpDevice) dev = wrapped_device_new ();
  g_autoptr(GBytes) payload = ec_on_payload (dev);
  g_autoptr(FpDevice) direct_dev = fixture_device_new ();
  g_autoptr(GBytes) direct_payload = ec_on_payload (direct_dev);

  g_assert_cmpmem (g_bytes_get_data (payload, NULL), 3, wrapped, 3);
  g_assert_cmpmem (g_bytes_get_data (direct_payload, NULL), 3, direct, 3);
}

static void
register_wrapped_tests (void)
{
  g_test_add_func ("/goodix53x5/wrapped/pack-header", test_wrapped_pack_header);
  g_test_add_func ("/goodix53x5/wrapped/pack-header-rejects", test_wrapped_pack_header_rejects);
  g_test_add_func ("/goodix53x5/wrapped/bad-header-drops-stream",
                   test_wrapped_bad_header_drops_stream);
  g_test_add_func ("/goodix53x5/wrapped/reader-error-drops-stream",
                   test_wrapped_reader_error_drops_stream);
  g_test_add_func ("/goodix53x5/wrapped/restart-rearm-yields-to-stop",
                   test_wrapped_restart_rearm_yields_to_stop);
  g_test_add_func ("/goodix53x5/wrapped/tls-truncated-record",
                   test_wrapped_tls_truncated_record);
  g_test_add_func ("/goodix53x5/wrapped/tls-handshake-limit",
                   test_wrapped_tls_handshake_limit);
  g_test_add_func ("/goodix53x5/wrapped/image-check", test_wrapped_image_check);
  g_test_add_func ("/goodix53x5/wrapped/first-image-error-restarts",
                   test_wrapped_first_image_error_restarts);
  g_test_add_func ("/goodix53x5/wrapped/open-order", test_wrapped_open_order);
  g_test_add_func ("/goodix53x5/wrapped/open-unacked-reply", test_wrapped_open_unacked_reply);
  g_test_add_func ("/goodix53x5/wrapped/open-foreign-firmware",
                   test_wrapped_open_foreign_firmware);
  g_test_add_func ("/goodix53x5/wrapped/open-unreadable-firmware",
                   test_wrapped_open_unreadable_firmware);
  g_test_add_func ("/goodix53x5/wrapped/open-foreign-psk", test_wrapped_open_foreign_psk);
  g_test_add_func ("/goodix53x5/wrapped/write-guard", test_wrapped_write_guard);
  g_test_add_func ("/goodix53x5/wrapped/ack-reports-config-loss",
                   test_wrapped_ack_reports_config_loss);
  g_test_add_func ("/goodix53x5/wrapped/command-budgets", test_wrapped_command_budgets);
  g_test_add_func ("/goodix53x5/wrapped/ec-on-payload", test_wrapped_ec_on_payload);
  g_test_add_func ("/goodix53x5/wrapped/d0-requests-reconnect",
                   test_wrapped_d0_requests_reconnect);
}
