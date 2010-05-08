/**
 * HTTP/HTTPS protocol support 
 *
 * Copyright (C) 2000-2009 by
 * Jeffrey Fulmer - <jeff@joedog.org>, et al. 
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
 */
#include <setup.h>
#include <http.h>
#include <stdio.h>
#include <stdarg.h>
#include <cookie.h>
#include <string.h>
#include <util.h>
#include <joedog/defs.h>

#define MAXFILE 10240

private char *__parse_pair(char **str);
private char *__dequote(char *str);

/**
 * HTTPS tunnel; set up a secure tunnel with the
 * proxy server. CONNECT server:port HTTP/1.0
 */
BOOLEAN
https_tunnel_request(CONN *C, char *host, int port)
{
  size_t  rlen, n;
  char    request[256];

  if(C->prot == HTTPS && my.proxy.required){
    snprintf(
      request, sizeof(request),
      "CONNECT %s:%d HTTP/1.0\015\012"
      "User-agent: Proxy-User\015\012"
      "\015\012",
      host, port
    );    
    rlen = strlen(request); 
    if(my.debug || my.get){fprintf(stdout, "%s", request); fflush(stdout);}
    if((n = socket_write(C, request, rlen)) != rlen){
      NOTIFY(ERROR, "HTTP: unable to write to socket." );
      return FALSE;
    }
  } else {
    return FALSE; 
  }
  return TRUE;
}

int
https_tunnel_response(CONN *C)
{
  int  x, n;
  char c;
  char line[256];
  int  code = 100;

  while(TRUE){
    x = 0;
    memset( &line, 0, sizeof( line ));
    while((n = read(C->sock, &c, 1)) == 1){
      line[x] = c;
      if(my.debug || my.get){ printf("%c", c); fflush(stdout); }
      if((line[0] == '\n') || (line[1] == '\n')){
        return code;
      }
      if( line[x] == '\n' ) break;
      x ++;
    }
    line[x]=0;
    if( strncasecmp( line, "http", 4 ) == 0 ){
      code = atoi(line + 9);
    }
  }
}

/**
 * returns int, ( < 0 == error )
 * formats and sends an HTTP/1.0 request
 */
int
http_get(CONN *C, URL *U)
{
  int  rlen;
  char *protocol; 
  char *keepalive;
  char hoststr[512];
  char authwww[512];
  char authpxy[512];
  char request[REQBUF+MAX_COOKIE_SIZE+8];  
  char portstr[16];
  char fullpath[4096];
  char cookie[MAX_COOKIE_SIZE+8];
  time_t now;
  char *ifmod = url_get_if_modified_since(U);
  char *ifnon = url_get_etag(U);

  now = time(NULL);

  memset(hoststr, 0, sizeof hoststr);
  memset(cookie,  0, sizeof cookie);
  memset(request, 0, sizeof request);
  memset(portstr, 0, sizeof portstr);

  /* Request path based on proxy settings */
  if(my.proxy.required){
    sprintf(
      fullpath, "%s://%s:%d%s", C->prot == HTTP?"http":"https", U->hostname, U->port, U->pathname 
    );
  } else {
    sprintf(fullpath, "%s", U->pathname);
  }

  if((U->port==80 && C->prot==HTTP) || (U->port==443 && C->prot==HTTPS)){
    portstr[0] = '\0';  
  } else {
    snprintf(portstr, sizeof portstr, ":%d", U->port);
  }

  /* HTTP protocol string */
  protocol  = (my.protocol == TRUE)?"HTTP/1.1":"HTTP/1.0";
  keepalive = (C->connection.keepalive == TRUE)?"keep-alive":"close";
  get_cookie_header(pthread_self(), U->hostname, cookie); 
  if(C->auth.www){
    if(C->auth.type.www==DIGEST){
      char *tmp;
      tmp = digest_generate_authorization(C->auth.wwwchlg, C->auth.wwwcred, "GET", fullpath);
      rlen = snprintf(authwww, sizeof(authwww), "Authorization: %s\015\012", tmp);
      free(tmp);
    } else {
      rlen = snprintf(authwww, sizeof(authwww), "Authorization: Basic %s\015\012", my.auth.encode);
    }
  }
  if(C->auth.proxy){
    if(C->auth.type.proxy==DIGEST){
      char *tmp;

      tmp = digest_generate_authorization(C->auth.proxychlg, C->auth.proxycred, "GET", fullpath);
      rlen = snprintf( authpxy, sizeof(authpxy), "Proxy-Authorization: %s\015\012", tmp);
      free(tmp);
    } else  {
      rlen = snprintf( authpxy, sizeof(authpxy), "Proxy-Authorization: Basic %s\015\012", my.proxy.encode);
    }
  }

  /* Only send the Host header if one wasn't provided. */
  if(strncasestr(my.extra, "host:", sizeof(my.extra)) == NULL){
    rlen = snprintf(hoststr, sizeof(hoststr), "Host: %s%s\015\012", U->hostname, portstr);
  }

  /** 
   * build a request string to pass to the server       
   */
  rlen = snprintf(
    request, sizeof( request ),
    "GET %s %s\015\012"                    /* fullpath, protocol     */
    "%s"                                   /* hoststr                */
    "%s"                                   /* authwww   or empty str */
    "%s"                                   /* authproxy or empty str */
    "%s"                                   /* cookie    or empty str */
    "%s"                                   /* ifmod     or empty str */
    "%s"                                   /* ifnon     or empty str */
    "Accept: */*\015\012"                  /*             */
    "Accept-Encoding: %s\015\012"          /* my.encoding */
    "User-Agent: %s\015\012"               /* my uagent   */
    "%s"                                   /* my.extra    */
    "Connection: %s\015\012\015\012",      /* keepalive   */
    fullpath, protocol, hoststr,
    (C->auth.www==TRUE)?authwww:"",
    (C->auth.proxy==TRUE)?authpxy:"",
    (strlen(cookie) > 8)?cookie:"", 
    (ifmod!=NULL)?ifmod:"",
    (ifnon!=NULL)?ifnon:"",
    my.encoding, my.uagent, my.extra, keepalive 
  );
 
  if(my.debug || my.get){ printf("%s\n", request); fflush(stdout); }
  if(rlen < 0 || rlen > (int)sizeof(request)){ 
    NOTIFY(FATAL, "HTTP GET: request buffer overrun!");
  }
  if((socket_write(C, request, rlen)) < 0){
    xfree(ifmod);
    xfree(ifnon);
    return -1;
  }
   
  xfree(ifmod);
  xfree(ifnon);
  return 0;
}

/**
 * returns int, ( < 0 == error )
 * formats and sends an HTTP/1.0 request
 */
int
http_post(CONN *C, URL *U)
{
  int  rlen;
  char hoststr[128];
  char authwww[128];
  char authpxy[128]; 
  char request[REQBUF+POSTBUF+MAX_COOKIE_SIZE+8]; 
  char portstr[16];
  char *protocol; 
  char *keepalive;
  char cookie[MAX_COOKIE_SIZE];
  char fullpath[4096];

  memset(hoststr, 0, sizeof(hoststr));
  memset(cookie,  0, sizeof(cookie));
  memset(request, 0, sizeof(request));
  memset(portstr, 0, sizeof portstr);

  if(my.proxy.required){
   sprintf(
      fullpath, 
      "%s://%s:%d%s", 
      C->prot == 0?"http":"https", U->hostname, U->port, U->pathname
    ); 
  } else {
    sprintf(fullpath, "%s", U->pathname);
  }

  if((U->port==80 && C->prot==HTTP) || (U->port==443 && C->prot==HTTPS)){
    portstr[0] = '\0';  ;
  } else {
    snprintf(portstr, sizeof portstr, ":%d", U->port);
  }

  /* HTTP protocol string */
  protocol  = (my.protocol == TRUE)?"HTTP/1.1":"HTTP/1.0";
  keepalive = (C->connection.keepalive == TRUE)?"keep-alive":"close";
  get_cookie_header(pthread_self(), U->hostname, cookie);
  if( C->auth.www ){
    if(C->auth.type.www==DIGEST){
      char *tmp;

      tmp = digest_generate_authorization(C->auth.wwwchlg, C->auth.wwwcred, "GET", fullpath);
      rlen = snprintf( authwww, sizeof(authwww), "Authorization: %s\015\012", tmp);
      free(tmp);
    } else {
      rlen = snprintf( authwww, sizeof(authwww), "Authorization: Basic %s\015\012", my.auth.encode);
    }
  }
  if( C->auth.proxy ){
    if(C->auth.type.proxy==DIGEST){
      char *tmp;

      tmp = digest_generate_authorization(C->auth.proxychlg, C->auth.proxycred, "GET", fullpath);
      rlen = snprintf( authpxy, sizeof(authpxy), "Proxy-Authorization: %s\015\012", tmp);
      free(tmp);
    } else  {
      rlen = snprintf( authpxy, sizeof(authpxy), "Proxy-Authorization: Basic %s\015\012", my.proxy.encode);
    }
  }

  /* Only send the Host header if one wasn't provided. */
  if(strncasestr(my.extra, "host:", sizeof(my.extra)) == NULL){
    rlen = snprintf(hoststr, sizeof(hoststr), "Host: %s%s\015\012", U->hostname, portstr);
  }

  /* build a request string to
     pass to the server       */
  rlen = snprintf(
    request, sizeof(request),
    "POST %s %s\015\012"
    "%s"
    "%s"
    "%s"
    "%s"
    "Accept: */*\015\012"
    "Accept-Encoding: %s\015\012"
    "User-Agent: %s\015\012%s"
    "Connection: %s\015\012"
    "Content-type: %s\015\012"
    "Content-length: %ld\015\012\015\012",
    fullpath, protocol, hoststr,
    (C->auth.www==TRUE)?authwww:"",
    (C->auth.proxy==TRUE)?authpxy:"",
    (strlen(cookie) > 8)?cookie:"", 
    my.encoding, my.uagent, my.extra, keepalive, U->conttype, (long)U->postlen
  ); 

  if(rlen + U->postlen < sizeof(request)){
    memcpy(request + rlen, U->postdata, U->postlen);
    request[rlen+U->postlen] = 0;
  }
  rlen += U->postlen;
  
  if(my.debug || my.get){ printf("%s\n", request); fflush(stdout); }
  if(rlen<0 || rlen>(int)sizeof(request)){
    NOTIFY(FATAL, "HTTP POST: request buffer overrun! Unable to continue..."); 
  }
  if((socket_write(C, request, rlen)) < 0){
    return -1;
  }

  return 0;
}

void
http_free_headers(HEADERS *h)
{
  xfree(h->redirect);
  xfree(h->auth.realm.proxy);
  xfree(h->auth.realm.www);
  xfree(h);
}

/**
 * returns HEADERS struct
 * reads from http/https socket and parses
 * header information into the struct.
 */
HEADERS *
http_read_headers(CONN *C, URL *U)
{ 
  int  x;           /* while loop index      */
  int  n;           /* assign socket_read    */
  char c;           /* assign char read      */
  HEADERS *h;       /* struct to hold it all */
  char line[MAX_COOKIE_SIZE];  /* assign chars read     */
  
  h = xcalloc(sizeof(HEADERS), 1);
  
  while(TRUE){
    x = 0;
    memset(&line, 0, MAX_COOKIE_SIZE);
    while((n = socket_read(C, &c, 1)) == 1){
      if(x < MAX_COOKIE_SIZE - 1)
        line[x] = c; 
      else 
        line[x] = '\n';
      if(my.debug || my.get){ printf("%c", c ); fflush(stdout); }
      if((line[0] == '\n') || (line[1] == '\n')){ 
        return h;
      }
      if(line[x] == '\n') break;
      x ++;
    }
    line[x]=0;
    /* strip trailing CR */
    if(x > 0 && line[x-1] == '\r') line[x-1]=0;
    if( strncasecmp(line, "http", 4) == 0){
      strncpy( h->head, line, 8);
      h->code = atoi(line + 9); 
    }
    if(strncasecmp(line, "content-length: ", 16) == 0){ 
      C->content.length = atoi(line + 16); 
    }
    if(strncasecmp(line, "set-cookie: ", 12) == 0){
      if(my.cookies){
        memset(h->cookie, 0, sizeof(h->cookie));
        strncpy(h->cookie, line+12, strlen(line));
        add_cookie(pthread_self(), U->hostname, h->cookie);
      }
    }
    if(strncasecmp(line, "connection: ", 12 ) == 0){
      if(strncasecmp(line+12, "keep-alive", 10) == 0){
        h->keepalive = 1;
      } else if(strncasecmp(line+12, "close", 5) == 0){
        h->keepalive = 0;
      }
    }
    if(strncasecmp(line, "keep-alive: ", 12) == 0){
      char *tmp    = "";
      char *option = "", *value = "";
      char *newline = (char*)line;
      while((tmp = __parse_pair(&newline)) != NULL){
        option = tmp;
        while(*tmp && !ISSPACE((int)*tmp) && !ISSEPARATOR(*tmp))
          tmp++;
        *tmp++=0;
        while(ISSPACE((int)*tmp) || ISSEPARATOR(*tmp))
          tmp++;
        value  = tmp;
        while(*tmp)
          tmp++;  
        if(!strncasecmp(option, "timeout", 7)){
          if(value != NULL){
            C->connection.timeout = atoi(value);
          } else {
            C->connection.timeout = 15;
          }
        }
        if(!strncasecmp(option, "max", 3)){
          if(value != NULL){
            C->connection.max = atoi(value);
          } else {
            C->connection.max = 0;
          }
        }
      }
    }
    if(strncasecmp(line, "location: ", 10) == 0){
      size_t len  = strlen(line);
      h->redirect = xmalloc(len);
      memcpy(h->redirect, line+10, len-10);
      h->redirect[len-10] = 0;
    }
    if(strncasecmp(line, "last-modified: ", 15) == 0){
      char *date;
      size_t len = strlen(line);
      if(my.cache){
        date = xmalloc(len);
        memcpy(date, line+15, len-14);
        url_set_last_modified(U, date);
        xfree(date); 
      }
    }
    if(strncasecmp(line, "etag: ", 6) == 0){
      char   *etag;
      size_t len = strlen(line);
      if(my.cache){
        etag = xmalloc(len);
        memcpy(etag, line+6, len-5);
        etag[len-1] = '\0';
        url_set_etag(U, etag);
        xfree(etag);
      }
    }
    if(strncasecmp(line, "www-authenticate: ", 18) == 0){
      char *tmp     = ""; 
      char *option  = "", *value = "";
      char *newline = (char*)line;
      if(strncasecmp(line+18, "digest", 6) == 0){
        newline += 24;
        h->auth.type.www      = DIGEST;
        h->auth.challenge.www = xstrdup(line+18);
      } else {
        newline += 23;
        h->auth.type.www = BASIC;
      }
      while((tmp = __parse_pair(&newline)) != NULL){
        option = tmp; 
        while(*tmp && !ISSPACE((int)*tmp) && !ISSEPARATOR(*tmp))
          tmp++;
        *tmp++=0;
        while(ISSPACE((int)*tmp) || ISSEPARATOR(*tmp))
          tmp++; 
        value  = tmp;
        while(*tmp)
          tmp++;
        if(!strncasecmp(option, "realm", 5)){
          if(value != NULL){
	    h->auth.realm.www = xstrdup(__dequote(value));
          } else {
            h->auth.realm.www = xstrdup("");
          }
        }
      } /* end of parse pairs */
    } 
    if(strncasecmp(line, "proxy-authenticate: ", 20) == 0){
      char *tmp     = ""; 
      char *option  = "", *value = "";
      char *newline = (char*)line;
      if(strncasecmp(line+20, "digest", 6) == 0){
        newline += 26;
        h->auth.type.proxy      = DIGEST;
        h->auth.challenge.proxy = xstrdup(line+20);
      } else {
        newline += 25;
        h->auth.type.proxy = BASIC;
      }
      while((tmp = __parse_pair(&newline)) != NULL){
        option = tmp; 
        while(*tmp && !ISSPACE((int)*tmp) && !ISSEPARATOR(*tmp))
          tmp++;
        *tmp++=0;
        while(ISSPACE((int)*tmp) || ISSEPARATOR(*tmp))
          tmp++; 
        value  = tmp;
        while(*tmp)
          tmp++;
        if(!strncasecmp(option, "realm", 5)){
          if(value != NULL){
	    h->auth.realm.proxy = xstrdup(__dequote(value));
          } else {
            h->auth.realm.proxy = xstrdup("");
          }
        }
      } /* end of parse pairs */
    }
    if(strncasecmp(line, "transfer-encoding: ", 19) == 0){
      if(strncasecmp(line+20, "chunked", 7)){
        C->content.transfer = CHUNKED; 
      } else if(strncasecmp(line+20, "trailer", 7)){
        C->content.transfer = TRAILER; 
      } else {
        C->content.transfer = NONE;
      }
    }
    if(strncasecmp(line, "expires: ", 9) == 0){
      /* printf("%s\n", line+10);  */
    }
    if(strncasecmp(line, "cache-control: ", 15) == 0){
      /* printf("%s\n", line+15); */
    }
    if(n <=  0){ 
      debug("read error: %s:%d", __FILE__, __LINE__);
      http_free_headers(h);
      return(NULL); 
    } /* socket closed */
  } /* end of while TRUE */

  return h;
}

int
http_chunk_size(CONN *C)
{
  int    n;
  char   *end;
  size_t length;

  memset(C->chkbuf, 0, sizeof(C->chkbuf));
  if((n = socket_readline(C, C->chkbuf, sizeof(C->chkbuf))) < 1){
    NOTIFY(WARNING, "HTTP: unable to determine chunk size");
    return -1;
  }

  if(((C->chkbuf[0] == '\n')||(strlen(C->chkbuf)==0)||(C->chkbuf[0] == '\r'))){
    return -1;
  }
 
  errno  = 0;
  if(!isxdigit((unsigned)*C->chkbuf))
    return -1;
  length = strtoul(C->chkbuf, &end, 16);
  if((errno == ERANGE) || (end == C->chkbuf)){
    NOTIFY(WARNING, "HTTP: invalid chunk line %s\n", C->chkbuf);
    return 0;
  } else {
    return length;
  }
  return -1;
}
  
/**
 * returns ssize_t
 */
ssize_t
http_read(CONN *C)
{ 
  int    n      = 0;
  int    chunk  = 0;
  size_t bytes  = 0;
  size_t length = 0;
  static char body[MAXFILE];

  if(C == NULL) NOTIFY(FATAL, "Connection is NULL! Unable to proceded"); 

  if(C->content.length > 0){
    length = (C->content.length < MAXFILE)?C->content.length:MAXFILE;
    do {
      memset(body, 0, sizeof(body));
      if(( n = socket_read(C, body, length)) == 0 )
        break;
      bytes += n;
      length = (C->content.length - bytes < MAXFILE)?C->content.length-bytes:MAXFILE;
    } while(bytes < C->content.length); 
  } else if(my.chunked && C->content.transfer == CHUNKED) {
    int tries = 0;
    while(tries < 256) {
      chunk = http_chunk_size(C);
      if(chunk == 0)
        break;
      else if(chunk < 0) {
        tries ++;
        continue;
      }
      do {
        int n;
        memset(body, 0, MAXFILE);
        n = socket_read(C, body, (chunk>MAXFILE)?MAXFILE:chunk);
        chunk -= n;
        bytes += n;
      } while(chunk > 0);
    }
  } else {
    do {
      memset(body, 0, sizeof(body));
      if((n = socket_read(C, body, sizeof(body))) == 0)
        break;
      bytes += n;
    } while(TRUE);
  }

  return(bytes);
}


/**
 * parses option=value pairs from an
 * http header, see keep-alive: above
 * while(( tmp = __parse_pair( &newline )) != NULL ){
 *   do_something( tmp );
 * }
 */
private char *
__parse_pair(char **str)
{
  int  okay  = 0;
  char *p    = *str;
  char *pair = NULL;
 
  if( !str || !*str ) return NULL;
  /**
   * strip the header label
   */
  while( *p && *p != ' ' )
    p++;
  *p++=0;
  if( !*p ){
    *str   = p;
    return NULL;
  }
 
  pair = p;
  while( *p && *p != ';' && *p != ',' ){
    if( !*p ){
      *str = p;
      return NULL;
    }
    if( *p == '=' ) okay = 1;
    p++;
  }
  *p++ = 0;
  *str = p;
 
  if( okay )
    return pair;
  else
    return NULL;
} 

char *
__rquote(char *str)
{
  char *ptr;
  int   len;

  len = strlen(str);
  for(ptr = str + len - 1; ptr >= str && ISQUOTE((int)*ptr ); --ptr);

  ptr[1] = '\0';

  return str;
}

char *
__lquote(char *str)
{
  char *ptr;
  int  len;

  for(ptr = str; *ptr && ISQUOTE((int)*ptr); ++ptr);

  len = strlen(ptr);
  memmove(str, ptr, len + 1);

  return str;
}

char *
__dequote(char *str)
{
  char *ptr;
  ptr = __rquote(str);
  str = __lquote(ptr);
  return str;
}
