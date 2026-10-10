/*
 * Goodix 53x5 driver for libfprint — GM168SEC bring-up
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "driver-private.h"
#include "device/commands.h"
#include "device/session.h"
#include "family/gm168sec/gm168sec.h"

typedef enum {
  GOODIX_GM168SEC_OPEN_PROBE,
  GOODIX_GM168SEC_OPEN_PSK_READ,
  GOODIX_GM168SEC_OPEN_PSK_CHECK,
  GOODIX_GM168SEC_OPEN_RESET,
  GOODIX_GM168SEC_OPEN_READ_OTP,
  GOODIX_GM168SEC_OPEN_PARSE_OTP,
  GOODIX_GM168SEC_OPEN_CHANNEL,
  GOODIX_GM168SEC_OPEN_NUM_STATES,
} GoodixGm168secOpenState;

#ifdef GOODIX53X5_DEBUG
static const gchar *
goodix_gm168sec_open_state_name (GoodixGm168secOpenState state)
{
  switch (state)
    {
    case GOODIX_GM168SEC_OPEN_PROBE:
      return "ping";
    case GOODIX_GM168SEC_OPEN_PSK_READ:
      return "early_psk_read";
    case GOODIX_GM168SEC_OPEN_PSK_CHECK:
      return "early_psk_check";
    case GOODIX_GM168SEC_OPEN_RESET:
      return "reset";
    case GOODIX_GM168SEC_OPEN_READ_OTP:
      return "read_otp";
    case GOODIX_GM168SEC_OPEN_PARSE_OTP:
      return "parse_otp";
    case GOODIX_GM168SEC_OPEN_CHANNEL:
      return "gtls_client_hello";
    case GOODIX_GM168SEC_OPEN_NUM_STATES:
    default:
      return "unknown";
    }
}
#endif

/* Brings a 533c up to an established TLS session in the vendor's order:
 * SelfCheck's firmware reads, the PSK check the vendor makes before it
 * resets the sensor, the chip ID read after a reset asking for the IRQ
 * reply, the OTP, then the handshake. The driver never writes a PSK here,
 * so one that does not match fails open. */
static void
goodix_gm168sec_open_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix53x5 *self = FPI_DEVICE_GOODIX53X5 (dev);
  GoodixGm168secOpenState state = fpi_ssm_get_cur_state (ssm);

  goodix_debug_timing_open_state (self, dev, goodix_gm168sec_open_state_name (state),
                                  g_get_monotonic_time ());

  switch (state)
    {
    case GOODIX_GM168SEC_OPEN_PROBE:
      /* SelfCheck reads, then wakes and reads once more. */
      goodix_open_probe (ssm, dev, 2, goodix_gm168sec_check_firmware);
      break;

    case GOODIX_GM168SEC_OPEN_PSK_READ:
      {
        g_autoptr(GError) error = NULL;

        if (!goodix_load_psk (self, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }
        goodix_cmd_preset_read (ssm, dev, GOODIX_WRAPPED_PSK_HASH_TYPE, GOODIX_PSK_HASH_LEN);
      }
      break;

    case GOODIX_GM168SEC_OPEN_PSK_CHECK:
      {
        GError *error = NULL;

        if (!goodix_require_current_psk (dev, GOODIX_WRAPPED_PSK_HASH_TYPE, &error))
          fpi_ssm_mark_failed (ssm, error);
        else
          fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_GM168SEC_OPEN_RESET:
      goodix_open_identify_chip (ssm, dev, TRUE);
      break;

    case GOODIX_GM168SEC_OPEN_READ_OTP:
      goodix_cmd_read_otp (ssm, dev);
      break;

    case GOODIX_GM168SEC_OPEN_PARSE_OTP:
      {
        g_autoptr(GError) error = NULL;

        if (!goodix_open_parse_otp (dev, &error))
          {
            fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
            return;
          }
        fpi_ssm_next_state (ssm);
      }
      break;

    case GOODIX_GM168SEC_OPEN_CHANNEL:
      goodix_open_channel (ssm, dev);
      break;

    case GOODIX_GM168SEC_OPEN_NUM_STATES:
      g_assert_not_reached ();
      break;
    }
}

FpiSsm *
goodix_gm168sec_open_new (FpDevice *dev)
{
  return fpi_ssm_new (dev, goodix_gm168sec_open_handler, GOODIX_GM168SEC_OPEN_NUM_STATES);
}
