/**
 * URL support
 *
 * Copyright (C) 2000-2006 Jeffrey Fulmer <jeff@joedog.org>
 * This file is part of Siege
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
#ifndef  URL_H
#define  URL_H
#include <stdlib.h>
#include <joedog/boolean.h>

#define MAX_URL       4096

/**
 * client data
 */
typedef enum {
  URL_GET   = 0,
  URL_POST  = 1
} DIRECTIVE;

/**
 * enum PROTOCOL
 * tcp/ip protocol
 */
typedef enum PROTOCOL{
  HTTP        = 0,
  HTTPS       = 1,
  UNSUPPORTED = 2
} PROTOCOL;


/**
 * URL struct URL
 */
typedef struct
{
  int       urlid;         /* ADDED BY jason, UNIQUE ID   */
  PROTOCOL  protocol;      /* currently only http/https   */
  char      *hostname;     /* DNS entry or IP address     */
  int       port;          /* tcp port num, defs: 80, 443 */
  char      *pathname;     /* path to http resource.      */
  DIRECTIVE calltype;      /* request: GET/POST/HEAD etc. */
  size_t    postlen;       /* length of POST data         */
  char      *postdata;
  char      *posttemp;
  char      *conttype;
  char      url[MAX_URL];
  time_t    expires;
  time_t    modified;
  BOOLEAN   cached;
  char      *etag;
} URL;

int      protocol_length(char *url); 
BOOLEAN  is_supported(char* url);
int      get_default_port(PROTOCOL p);
PROTOCOL get_protocol(const char *url);
void     insert_childid(URL *U, int mypid);
void     url_set_last_modified(URL *U, char *date);
void     url_set_etag(URL *U, char *etag);
void     url_set_expires(URL *U, int secs);
char     *url_get_if_modified_since(URL *U);
char     *url_get_etag(URL *U);
URL      *build_url(char *url, int defaultport, int id);
URL      *add_url(char *url, int id);

#endif/*URL_H*/
