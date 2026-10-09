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

/* Establishes @tls with an in-memory client, the sensor's role. */
static SSL *
connect_client (GoodixTls *tls, SSL_CTX *ctx, BIO **client_in, BIO **client_out)
{
  SSL *client = SSL_new (ctx);
  g_autoptr(GBytes) to_server = NULL;
  int rounds = 0;

  *client_in = BIO_new (BIO_s_mem ());
  *client_out = BIO_new (BIO_s_mem ());
  BIO_set_mem_eof_return (*client_in, -1);
  SSL_set_bio (client, *client_in, *client_out);
  SSL_set_connect_state (client);

  while (!goodix_tls_established (tls) || SSL_do_handshake (client) != 1)
    {
      g_autoptr(GBytes) to_client = NULL;
      g_autoptr(GError) error = NULL;
      gsize len;
      const guint8 *data;

      g_assert_cmpint (++rounds, <, 10);
      SSL_do_handshake (client);
      g_clear_pointer (&to_server, g_bytes_unref);
      to_server = take_bio (*client_out);
      data = g_bytes_get_data (to_server, &len);
      g_assert_true (goodix_tls_handshake (tls, data, len, &to_client, &error));
      if (to_client)
        BIO_write (*client_in, g_bytes_get_data (to_client, NULL),
                   g_bytes_get_size (to_client));
    }
  return client;
}

/* Returns @data sealed into a record by a new in-memory client, playing the
 * sensor, after it establishes a session with @tls. */
static GBytes *
client_record (GoodixTls *tls, const char *data, gsize len)
{
  SSL_CTX *ctx = SSL_CTX_new (TLS_client_method ());
  BIO *client_in, *client_out;
  SSL *client;
  GBytes *record;

  SSL_CTX_set_max_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_cipher_list (ctx, "PSK-AES128-CBC-SHA256");
  SSL_CTX_set_psk_client_callback (ctx, client_psk);
  client = connect_client (tls, ctx, &client_in, &client_out);
  g_assert_cmpint (SSL_write (client, data, len), ==, len);
  record = take_bio (client_out);
  SSL_free (client);
  SSL_CTX_free (ctx);
  return record;
}

/* A record cut short fails at once instead of corrupting the next one. */
static void
test_wrapped_tls_truncated_record (void)
{
  const guint8 psk[GOODIX_PSK_LEN] = { 0 };
  const char image[] = "image bytes";
  GoodixTls *tls = goodix_tls_new (psk, sizeof (psk), NULL);
  g_autoptr(GBytes) record = client_record (tls, image, sizeof (image));
  g_autofree guint8 *plain = NULL;
  gsize len, plain_len = 0;
  const guint8 *data = g_bytes_get_data (record, &len);

  g_test_expect_message ("libfprint-goodix53x5", G_LOG_LEVEL_WARNING,
                         "TLS record is incomplete");
  g_assert_null (goodix_tls_decrypt (tls, data, len - 1, &plain_len));
  g_test_assert_expected_messages ();
  goodix_tls_free (tls);

  tls = goodix_tls_new (psk, sizeof (psk), NULL);
  g_clear_pointer (&record, g_bytes_unref);
  record = client_record (tls, image, sizeof (image));
  data = g_bytes_get_data (record, &len);
  plain = goodix_tls_decrypt (tls, data, len, &plain_len);
  g_assert_cmpmem (plain, plain_len, image, sizeof (image));
  goodix_tls_free (tls);
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
}
