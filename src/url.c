/**
 * URL Processing
 *
 * Copyright (C) 2000-2007 by
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
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <setup.h>
#include <load.h>
#include <date.h>
#include <joedog/joedog.h>
#include <joedog/boolean.h>

/*HARDCODED ALERT*/
#define PLENGTH 84  /* length of the *prot[] array */

/** 
 * ALERT: using hardcoded array lengths below,
 * if you change this array, then redefine PLENGTH
 * 
 * Currently http(prot[25]) and https(prot[26]) are 
 * the only supported protocols.  But all w3c supported 
 * protocols are listed for URL evaluation.
 */  
static const char *prot[] = {
  "about:",      "addrbook:",  "acap:",      "afp:",
  "afs:",        "callto:",    "chttp:",     "cid:",
  "clsid:",      "data:",      "date:",      "DAV:",
  "dns:",        "eid:",       "fax:",       "file:",
  "finger:",     "freenet:",   "ftp:",       "gopher:",
  "gsm:",        "h323:",      "h324:",      "hdl:",
  "hnews:",      "http:",      "https:",     "iioploc:",
  "ilu:",        "imap:",      "IOR:",       "irc:",
  "isbn:",       "java:",      "JavaRMI:",   "javascript:",
  "jdbc:",       "ldap:",      "lid:",       "lifn:",
  "livescript:", "lrq:",       "mailto:",    "mailserver:",
  "md5:",        "mid:",       "mocha:",     "modem:",
  "news:",       "nfs:",       "nntp:",      "opaquelocktoken:"
  "path:",       "phone:",     "pop:",       "pop3:",
  "printer:",    "prospero:",  "res:",       "rtsp:",
  "rvp:",        "rwhois:",    "rx:",        "sdp:",
  "sip:",        "shttp:",     "snews:",     "STANF:",
  "t120:",       "tel:",       "telephone:", "telnet:",
  "tip:",        "tn3270:",    "tv:",        "uuid:",
  "urn:",        "vemmi:",     "videotex:",  "view:",
  "wais:",       "whois++:",   "whodp:",     "z39.50r:",
  "z39.50s:"
  
};

/**
 * int value of the length of the protocol 
 * string passed to the function.
 */     
int
protocol_length(char *url)
{
  int x;
  /** 
   * hardcoded protocol length!! see explanation above...
   */
  for(x = 0; x < PLENGTH; x ++){ 
    if(strncasecmp( url, prot[x], strlen( prot[x] )) == 0){
      return strlen(prot[x]);
    }
  } 
  return 0;	
}

/**
 * boolean, returns true if the protocol is 
 * supported by siege, false if it is not.
 */ 
BOOLEAN
is_supported(char* url)
{
  if( strncasecmp( url, prot[25], strlen( prot[25] )) == 0 )
    return TRUE;
#ifdef HAVE_SSL
  if( strncasecmp( url, prot[26], strlen( prot[26] )) == 0 )
    return TRUE;
#endif /* HAVE_SSL */
  
  return FALSE;
}

/**
 * get_protocol
 * returns protocol char*
 */
PROTOCOL
get_protocol(const char *url)
{
  if(strncasecmp(url, prot[25], strlen(prot[25])) == 0)
    return HTTP;
  if(strncasecmp(url, prot[26], strlen(prot[26])) == 0)
    #ifdef HAVE_SSL
      return HTTPS;
    #else
      return HTTP;
    #endif /* HAVE_SSL */
  else
    return UNSUPPORTED;
}

/**
 * get_default_port
 */
int
get_default_port(PROTOCOL p)
{
  if(p == HTTP)
    return 80;
  if(p == HTTPS)
    #ifdef HAVE_SSL
      return 443;
    #else
      return 80;
    #endif /* HAVE_SSL */
  else
    return 80; 
}

/**
 * insert_childid 
 * replaces all '+' characters in POST 
 * data with numbers derived from the process id.
 * return void
 */
void
insert_childid(URL *U, int mypid)
{
  int    i,j;
  char   *c, *f, *l;
  char   pidbuf[6];
 
  sprintf( pidbuf, "%5.5d", mypid );
 
  for( i=0; i<5; i++ ){
    if( U->posttemp ){
      f = strchr(U->posttemp, '+');
      l = strrchr(U->posttemp, '+');
      /* Start at last occurrence of '+' and move to first */
      for (j=sizeof(pidbuf)-1, c=l; c >= f; j--, c--){
        if (*c == '+'){
          *c = pidbuf[j-1];
        }
        if (j == 0){
          j=sizeof(pidbuf)-1;   /* Start over */
        }
      }
      /* Now that we're done, copy the new template to data */
      strcpy(U->postdata, U->posttemp);
    }
  }
}

void
url_set_expires(URL *U, int secs)
{
  time_t now;
 
  now  = time(NULL);
  U->expires = adjust(now, secs);  
  U->cached  = TRUE;

  return;
}

void
url_set_last_modified(URL *U, char *date)
{
  U->modified = strtotime(date);
  return; 
}

void 
url_set_etag(URL *U, char *etag)
{
  size_t len;
  if(empty(etag)) return;

  len = strlen(etag)+1;
  U->etag = xmalloc(len);
  memset(U->etag, 0, sizeof U->etag);
  strncpy(U->etag, etag, len);
  return;
}

char *
url_get_if_modified_since(URL *U)
{
  if(U->cached == FALSE){
    return NULL; 
  }

  return timetostr(&U->modified);
}

char *
url_get_etag(URL *U)
{
  char   *tag;
  size_t len;

  if(empty(U->etag)) return NULL; 

  len = strlen(U->etag) + 18;
  tag = xmalloc(len);
  memset(tag, 0, sizeof tag);

  snprintf(tag, len, "If-None-Match: %s\015\012", U->etag);
  return tag;
}

char *
url_encode(char *str)
{
  int size = 0;
  char *ch, *bk;
  char *p, *buf;
  static char unsafe[]     = "<>{}#%|\"\\^~[]`@:\033";
  static char char2hex[16] = "0123456789ABCDEF";

  bk = ch  = str;
  do {
    if(strchr(unsafe, *ch))
      size += 2;
    ch++; size ++;
  } while(*ch);

  buf = (char*)malloc(size +1);
  p   = buf;
  ch  = bk;
  do{
    if(strchr(unsafe, *ch)){
      const char c = *ch;
      *p++ = '%';
      *p++ = char2hex[(c >> 4) & 0xf];
      *p++ = char2hex[c & 0xf];
    } else {
      *p++ = *ch;
    }
    ch ++;
  } while(*ch);

  *p = '\0';
  return(buf);
}

/**
 * build_from_template 
 * builds POST data replacing all '*' 
 * characters with random numbers
 * returns void
 */
void
build_from_template(URL *U, int rand)
{
  char   *s=U->posttemp;
  char   *t=U->postdata;
  int    i,j,f,l;
  char   buf[9];
 
  sprintf(buf, "%8.8d", rand);
 
  f = strchr(s, '*')  -s;
  l = strrchr(s, '*') -s;
  /* Start at last occurrence of '+' and move to first */
  for (j=sizeof(buf)-1, i=l; i >= f; j--, i--){
    if (s[i] == '*'){
      t[i] = buf[j-1];
    } else {
      t[i] = s[i];
    }
    if (j == 0){
      j=sizeof(buf)-1;   /* Start over */
    }
  } 
}

/**
 * process_post_data
 * populates URL->postdata with POST information
 */
void
process_post_data(URL *U, char *datap)
{
  for(; isspace((unsigned int)*datap); datap++){
    /* Advance past white space */
  }
  if(*datap == '<'){
    datap++;
    load_file(U, datap);
    return;
  } else {
    U->postdata = xstrdup(datap);
    U->postlen  = strlen(U->postdata);
    U->conttype = xstrdup("application/x-www-form-urlencoded");
    return;
  }
  return;
}

URL *
build_url(char *url, int defaultport, int id)
{
  URL *U;                  /* defined in setup.h        */
  int mark[4] = {0,0,0,0}; /* placement counters.       */
  char *post_cmd=NULL;     /* POST directive for server */
  char *tmp;

  U = xcalloc(sizeof(URL), 1);
  U->urlid = id;
  U->expires  = 0;
  U->modified = 0;
  U->cached   = FALSE;
  
  post_cmd = strstr(url, " POST"); 

  if( post_cmd != NULL ){
    /* How do we deal with handling the multi-headed url_t arrays */
    U->calltype = URL_POST;
    *post_cmd = 0;
    post_cmd += 5;
    process_post_data(U, post_cmd);
  } else {
    U->calltype   = URL_GET;
    U->postdata   = NULL;
    U->posttemp   = NULL;
    U->postlen    = 0;
  }

  if ((mark[0] = protocol_length(url)) > 0 && is_supported(url) == TRUE) {
    mark[0] += 2;
  } else if((mark[0] = protocol_length(url)) > 0 && is_supported(url) == FALSE){
    U->protocol = UNSUPPORTED;
    mark[0]   += 2;
    NOTIFY(WARNING, "unsupported protocol");
    return NULL;
  } else {
    /* we are dealing with who knows what */
    tmp = (char*)strstr( url, "://" );
    if(tmp != NULL){
      mark[0] = (strlen(url) - (strlen(tmp) - 3));
    } else {
      mark[0] = 0;  /* no specified protocol, assuming http: */
    }
  }

  mark[1] = mark[0];
  while(url[mark[1]] && url[mark[1]] != ':' && url[mark[1]] != '/') mark[1]++; 

  if(url[mark[1]] == ':'){
    mark[3] = mark[1];
    while(url[mark[1]] && url[mark[1]] != '/'){
      mark[1]++;
    }
  } else { 
    mark[3] = mark[1]; 
  }

  if(url[mark[1]] == '/'){
     mark[2] = mark[1]; 
  } else { 
    mark[2] = strlen(url); 
  } 

  /* here we piece it all together */
  if( mark[0] == 0 ){
    U->protocol = HTTP;
  } else {
    U->protocol = get_protocol(url);
  }
 
  if(mark[0] != mark[3]){
    U->hostname = (char*)(substring(url, mark[0], (mark[3] - mark[0]))); 
  } else {
    NOTIFY(WARNING, "malformed URL: %s", url);
    return NULL;
  }
    
  if(mark[3] == mark[1]){
    if(defaultport < 0)
      U->port = get_default_port(U->protocol);
    else
      U->port = defaultport;
  } else {
    char *portstr = substring(url, mark[3]+1, (mark[2]-(mark[3]+1)));
    if(portstr != NULL){
      U->port = atoi(portstr);
    } else {
      U->port = 80;
    }
    xfree(portstr); 
  }

  tmp = substring(url, mark[2], strlen(url) - mark[2]);
  if(tmp == NULL){
    U->pathname = (char *)xstrdup("/"); 
  } else {
    U->pathname = (char *)xstrdup(tmp); 
  }

  U->pathname = (strlen(U->pathname)==0)?strcpy(U->pathname, "/"):U->pathname; 
  trim(U->pathname);

  snprintf(
    U->url, MAX_URL, "%s%s:%d%s", 
    (U->protocol==HTTP)?"http://":"https://", U->hostname, U->port, U->pathname
  );

  xfree(tmp);
  return(U);
}

/**
 * add_url
 * parses char * then populates and 
 * returns a URL with appropriate data.
 */
URL *
add_url(char *url, int id)
{
  URL *tmp_url;
  char *tmp;

  /**
   * check string integrity so we
   * can inform the user rather then
   * simply abort with an archaic msg.
   */
  if (!url) {
    NOTIFY(WARNING, "INVALID URL: <%s>", url);
    display_help();
  } 
  /**
   * freed in build_url()
   */
  tmp = (char*)xstrdup(url);
  tmp_url = build_url(tmp, -1, id);
  xfree(tmp);
  return tmp_url;
}


