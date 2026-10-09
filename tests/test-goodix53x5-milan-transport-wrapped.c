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
}
