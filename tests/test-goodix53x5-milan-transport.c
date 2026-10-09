/*
 * Goodix profile-9 transport/coordinator scheduling contracts.
 * Copyright (C) 2026 goodix53x5-libfprint contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* Keep the private production boundaries in one translation unit. The USB/time
 * fixture is separately compiled; these files own the existing case families. */
#include "test-goodix53x5-milan-transport-owners.h"
#include "test-goodix53x5-milan-transport-cases.h"

void
test_transport_wait_info (FpDevice *dev, guint *timeout, GCancellable **cancel)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixTransport *operation = self->transport;

  *timeout = operation && operation->deadline_us ?
             goodix_deadline_remaining (operation->deadline_us) : 0;
  *cancel = operation ? operation->cancellable : self->reader->cancel;
}

void
test_transport_wait_failed (FpDevice *dev, GError *error)
{
  GoodixTransport *operation = FPI_DEVICE_GOODIX53X5 (dev)->transport;

  g_assert_nonnull (operation);
  if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
    {
      g_assert_nonnull (operation->timer);
      g_clear_pointer (&operation->timer, g_source_destroy);
      goodix_transport_expired (dev, operation);
      g_error_free (error);
    }
  else
    {
      goodix_transport_complete (operation, error);
    }
}

static void
fixture_reader_joined (FpDevice *dev, gpointer data)
{
  g_assert_null (FPI_DEVICE_GOODIX53X5 (dev)->reader);
}

void
fixture_join_reader (FpDevice *dev)
{
  GoodixReader *reader = FPI_DEVICE_GOODIX53X5 (dev)->reader;
  gboolean pending = reader && reader->pending;

  goodix_transport_quiesce (dev, fixture_reader_joined, NULL);
  if (pending)
    fixture_complete (g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Joined reader"));
}

#include "test-goodix53x5-milan-transport-commands.c"
#include "test-goodix53x5-milan-transport-capture.c"
#include "test-goodix53x5-milan-transport-lifecycle.c"
#include "test-goodix53x5-milan-transport-wrapped.c"
/* An authenticated GTLS frame that is too short to decode fails the image
 * response, as before the variant interface; it must not leave an earlier
 * image to be returned. */
static void
test_gtls_undecodable_frame_fails_image (void)
{
  g_autoptr(FpDevice) dev = fixture_device_new ();
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixTransport operation = { .dev = dev };
  guint8 frame[8 + 11 + 32] = { 0x01, 0xaa, 0, 0, sizeof (frame) };
  guint8 *gea = frame + 8;
  guint8 hmac_data[4 + 11] = { 0 };
  guint32 crc;

  self->gtls.state = 5;
  /* Five stripped bytes, one pixel byte pair, then the CRC in device order. */
  crc = goodix_crypto_crc32_mpeg2 (gea + 5, 2);
  gea[7] = (crc >> 8) & 0xff;
  gea[8] = crc & 0xff;
  gea[9] = crc >> 24;
  gea[10] = (crc >> 16) & 0xff;
  memcpy (hmac_data + 4, gea, 11);
  goodix_crypto_hmac_sha256 (self->gtls.hmac_key, 32, hmac_data, sizeof (hmac_data),
                             frame + 8 + 11);

  g_test_expect_message ("libfprint-goodix53x5", G_LOG_LEVEL_WARNING,
                         "Truncated raw12 image payload*");
  g_assert_false (goodix_rx_image (&operation, frame, sizeof (frame)));
  g_test_assert_expected_messages ();
  g_assert_cmpuint (self->gtls.hmac_server_counter, ==, 1);
  g_assert_true (self->image_response_failed);
  fixture_join_reader (dev);
  g_clear_object (&action_cancel_token);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix53x5/gtls/undecodable-frame-fails-image",
                   test_gtls_undecodable_frame_fails_image);
  register_command_tests ();
  register_capture_tests ();
  register_lifecycle_tests ();
  register_wrapped_tests ();
  return g_test_run ();
}
