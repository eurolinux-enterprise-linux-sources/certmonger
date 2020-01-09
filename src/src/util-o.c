/*
 * Copyright (C) 2010 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include "util-o.h"

void
util_o_init(void)
{
#if defined(HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS) && HAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS
	OpenSSL_add_all_algorithms();
#elif defined(HAVE_DECL_OPENSSL_ADD_SSL_ALGORITHMS) && HAVE_DECL_OPENSSL_ADD_SSL_ALGORITHMS
	OpenSSL_add_ssl_algorithms();
#else
	SSL_library_init();
#endif
}
