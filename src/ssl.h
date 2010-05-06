/**
 * SSL Thread Safe Setup Functions.
 *
 * Copyright (C) 2002 by
 * Jeffrey Fulmer - <jdfulmer@armstrong.com>
 * This file is distributed as part of Siege
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * --
 */
#ifndef SSL_H
#define SSL_H

#ifdef  HAVE_CONFIG_H
# include <config.h>
#endif/*HAVE_CONFIG_H*/

#include <sock.h>
#include <joedog/boolean.h>

#include <pthread.h>
#ifdef HAVE_SSL
#ifdef  HAVE_E_OS_H
# include <openssl/e_os.h>
#endif/*HAVE_E_OSH*/ 
#ifdef  HAVE_E_OS2_H
# include <openssl/e_os2.h> 
#endif/*HAVE_E_OS2_H*/
#include <openssl/lhash.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#endif/*HAVE_SSL*/

BOOLEAN SSL_initialize(CONN *C);
void    SSL_thread_setup(void);
void    SSL_thread_cleanup(void);

#endif/*SSL_H*/

