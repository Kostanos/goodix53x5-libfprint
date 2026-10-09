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
/* A wrapped pack header reads back what it was written with, matches the
 * vendor driver's bytes, and is refused once its checksum is wrong. */
static void
test_wrapped_pack_header (void)
{
  const guint8 vendor[GOODIX_PACK_HEADER] = { 0xa0, 0x14, 0x00, 0xb4 };
  const guint8 msg[70] = { 0xa8, 0x03, 0x00 };
  guint8 header[GOODIX_PACK_HEADER];
  gsize framed_len, len;
  g_autofree guint8 *framed = goodix_frame_wrapped (GOODIX_PACK_MESSAGE, msg,
                                                    sizeof (msg), &framed_len);

  goodix_pack_write_header (header, GOODIX_PACK_MESSAGE, 0x14);
  g_assert_cmpmem (header, sizeof (header), vendor, sizeof (vendor));

  g_assert_cmpuint (framed_len, ==, 2 * GOODIX_USB_CHUNK_SIZE);
  g_assert_cmpuint (framed[0], ==, GOODIX_PACK_MESSAGE);
  g_assert_true (goodix_pack_read_header (framed, &len));
  g_assert_cmpmem (framed + GOODIX_PACK_HEADER, len, msg, sizeof (msg));

  framed[3]++;
  g_assert_false (goodix_pack_read_header (framed, &len));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix53x5/wrapped/pack-header", test_wrapped_pack_header);
  register_command_tests ();
  register_capture_tests ();
  register_lifecycle_tests ();
  return g_test_run ();
}
