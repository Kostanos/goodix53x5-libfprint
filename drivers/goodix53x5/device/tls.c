/*
 * Goodix 53x5 driver for libfprint — TLS-PSK for wrapped sensors
 * Copyright (C) 2026 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define FP_COMPONENT "goodix53x5"

#include "drivers_api.h"
#include "device/tls.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

/* The suite the sensor negotiates with a stock `openssl s_server -psk`. */
#define GOODIX_TLS_CIPHER "PSK-AES128-CBC-SHA256"
#define GOODIX_TLS_MAX_PSK 64

struct _GoodixTls
{
  SSL_CTX *ctx;
  SSL     *ssl;
  BIO     *in;   /* records from the sensor; owned by ssl */
  BIO     *out;  /* records for the sensor; owned by ssl */
  guint8   psk[GOODIX_TLS_MAX_PSK];
  gsize    psk_len;
};

static unsigned int
goodix_tls_psk_cb (SSL *ssl, const char *identity, unsigned char *psk,
                   unsigned int max_psk_len)
{
  GoodixTls *tls = SSL_get_app_data (ssl);

  /* The sensor's PSK identity is not checked, as openssl s_server does not. */
  if (tls->psk_len > max_psk_len)
    return 0;
  memcpy (psk, tls->psk, tls->psk_len);
  return tls->psk_len;
}

static void
goodix_tls_set_error (GError **error, const char *what)
{
  char buf[256] = "unknown error";
  unsigned long code = ERR_get_error ();

  if (code)
    ERR_error_string_n (code, buf, sizeof (buf));
  ERR_clear_error ();
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "TLS %s failed: %s", what, buf);
}

GoodixTls *
goodix_tls_new (const guint8 *psk, gsize psk_len, GError **error)
{
  GoodixTls *tls;

  g_return_val_if_fail (psk_len <= GOODIX_TLS_MAX_PSK, NULL);
  tls = g_new0 (GoodixTls, 1);
  memcpy (tls->psk, psk, psk_len);
  tls->psk_len = psk_len;

  tls->ctx = SSL_CTX_new (TLS_server_method ());
  if (!tls->ctx ||
      !SSL_CTX_set_min_proto_version (tls->ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version (tls->ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_cipher_list (tls->ctx, GOODIX_TLS_CIPHER))
    {
      goodix_tls_set_error (error, "setup");
      goodix_tls_free (tls);
      return NULL;
    }
  SSL_CTX_set_options (tls->ctx, SSL_OP_NO_TICKET);
  SSL_CTX_set_psk_server_callback (tls->ctx, goodix_tls_psk_cb);

  tls->ssl = SSL_new (tls->ctx);
  tls->in = BIO_new (BIO_s_mem ());
  tls->out = BIO_new (BIO_s_mem ());
  if (!tls->ssl || !tls->in || !tls->out)
    {
      BIO_free (tls->in);
      BIO_free (tls->out);
      tls->in = tls->out = NULL;
      goodix_tls_set_error (error, "setup");
      goodix_tls_free (tls);
      return NULL;
    }
  /* An empty input BIO means "wait for more", not end of stream. */
  BIO_set_mem_eof_return (tls->in, -1);
  SSL_set_bio (tls->ssl, tls->in, tls->out);
  SSL_set_app_data (tls->ssl, tls);
  SSL_set_accept_state (tls->ssl);
  return tls;
}

void
goodix_tls_free (GoodixTls *tls)
{
  if (!tls)
    return;
  SSL_free (tls->ssl);
  SSL_CTX_free (tls->ctx);
  OPENSSL_cleanse (tls->psk, sizeof (tls->psk));
  g_free (tls);
}

static GBytes *
goodix_tls_take_output (GoodixTls *tls)
{
  char *data;
  long len = BIO_get_mem_data (tls->out, &data);
  GBytes *out;

  if (len <= 0)
    return NULL;
  out = g_bytes_new (data, len);
  (void) BIO_reset (tls->out);
  return out;
}

gboolean
goodix_tls_handshake (GoodixTls    *tls,
                      const guint8 *in,
                      gsize         in_len,
                      GBytes      **out,
                      GError      **error)
{
  int ret;

  *out = NULL;
  if (in_len && BIO_write (tls->in, in, in_len) != (int) in_len)
    {
      goodix_tls_set_error (error, "input");
      return FALSE;
    }

  ret = SSL_do_handshake (tls->ssl);
  if (ret == 1 || SSL_get_error (tls->ssl, ret) == SSL_ERROR_WANT_READ)
    {
      *out = goodix_tls_take_output (tls);
      return TRUE;
    }

  goodix_tls_set_error (error, "handshake");
  return FALSE;
}

gboolean
goodix_tls_established (GoodixTls *tls)
{
  return SSL_is_init_finished (tls->ssl);
}

guint8 *
goodix_tls_decrypt (GoodixTls    *tls,
                    const guint8 *records,
                    gsize         records_len,
                    gsize        *out_len)
{
  g_autoptr(GByteArray) plain = g_byte_array_new ();
  guint8 buf[16 * 1024];
  int ret;

  if (BIO_write (tls->in, records, records_len) != (int) records_len)
    {
      ERR_clear_error ();
      return NULL;
    }

  while ((ret = SSL_read (tls->ssl, buf, sizeof (buf))) > 0)
    g_byte_array_append (plain, buf, ret);

  if (SSL_get_error (tls->ssl, ret) != SSL_ERROR_WANT_READ || !plain->len)
    {
      fp_warn ("TLS record did not authenticate");
      ERR_clear_error ();
      return NULL;
    }
  OPENSSL_cleanse (buf, sizeof (buf));

  *out_len = plain->len;
  return g_byte_array_free (g_steal_pointer (&plain), FALSE);
}
