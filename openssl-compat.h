#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include "util-internal.h"

#if defined(LIBRESSL_VERSION_NUMBER)
#error "Libevent requires OpenSSL >= 3.0.0; LibreSSL is not supported"
#endif

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
#error "Libevent requires OpenSSL >= 3.0.0"
#endif

#endif /* OPENSSL_COMPAT_H */
