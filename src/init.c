/**
 * Siege environment initialization.
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
#include <init.h>
#include <setup.h>
#include <auth.h>
#include <util.h>
#include <hash.h>
#include <eval.h>
#include <fcntl.h>
#include <version.h>
#include <joedog/boolean.h>
#include <joedog/defs.h>
#include <joedog/joedog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

int
init_config( void )
{
  char *e;
  int  res;
  struct stat buf;

  /* Check if we were passed the -R switch to use a different siegerc file.
   * If not, check for the presence of the SIEGERC variable, otherwise
   * use default of ~/.siegerc */
  if(strcmp(my.rc, "") == 0){
    if((e = getenv("SIEGERC")) != NULL){
      snprintf(my.rc, sizeof(my.rc), e);
    } else {
      snprintf(my.rc, sizeof(my.rc), "%s/.siegerc", getenv("HOME"));
      if (stat(my.rc, &buf) < 0 && errno == ENOENT) {
        snprintf(my.rc, sizeof(my.rc), CNF_FILE);
      }
    }
  } 

  my.debug          = FALSE;
  my.internet       = FALSE;
  my.config         = FALSE;
  my.cookies        = TRUE;
  my.csv            = FALSE;
  my.fullurl        = FALSE;
  my.secs           = -1;
  my.reps           = MAXREPS; 
  my.bids           = 5;
  my.login          = FALSE;
  my.failures       = 1024;
  my.failed         = 0;
  my.auth.encode    = xstrdup("");
  my.proxy.encode   = xstrdup("");
  my.proxy.required = FALSE;
  my.proxy.port     = 80; 
  my.timeout        = 30;
  my.chunked        = FALSE;
  my.extra[0]       = 0;
  my.follow         = TRUE;
  my.zero_ok        = TRUE; 
  my.signaled       = 0;
  my.ssl_timeout    = 300;
  my.ssl_cert       = NULL;
  my.ssl_key        = NULL;
  my.ssl_ciphers    = NULL; 

  if((res = pthread_mutex_init(&(my.lock), NULL)) != 0)
    NOTIFY(FATAL, "unable to initiate lock");
  if((res = pthread_cond_init(&(my.cond), NULL )) != 0)
    NOTIFY(FATAL, "unable to initiate condition");

  if(load_conf(my.rc) < 0){
    fprintf( stderr, "****************************************************\n" );
    fprintf( stderr, "siege: could not open %s\n", my.rc );
    fprintf( stderr, "run \'siege.config\' to generate a new .siegerc file\n" );
    fprintf( stderr, "****************************************************\n" );
    return -1;
  }
  
  if(strlen(my.file) < 1){ 
    strcpy( my.file, SIEGE_HOME );
    strcat( my.file, "/etc/urls.txt" );
  }

  if(strlen(my.uagent) < 1) 
    snprintf( 
      my.uagent, sizeof(my.uagent),
      "JoeDog/1.00 [en] (X11; I; Siege %s)", version_string 
    );

  if(strlen(my.encoding) < 1)
    snprintf(
      my.encoding, sizeof(my.encoding), "*"
    );

  if(strlen(my.logfile) < 1) 
    snprintf( 
      my.logfile, sizeof( my.logfile ),
      "%s", LOG_FILE 
    );
  /**
   * DEPRECATED!! username and password are being
   * phased out in favor of my.auth.head
   */
  if(( my.username && strlen(my.username) > 0 ) &&
    (  my.password && strlen(my.password) > 0 )){
    add_authorization(WWW, my.username, my.password, "all"); 
  }
  if(my.proxy.hostname && strlen(my.proxy.hostname) > 0){
    my.proxy.required = TRUE;
  } 

  return 0;  
}

int
show_config( int EXIT )
{
  printf( "CURRENT  SIEGE  CONFIGURATION\n" );
  printf( "%s\n", my.uagent ); 
  printf( "Edit the resource file to change the settings.\n" );
  printf( "----------------------------------------------\n" );
  printf( "version:                        %s\n", version_string );
  printf( "verbose:                        %s\n", my.verbose?"true":"false" );
  printf( "debug:                          %s\n", my.debug?"true":"false" );
  printf( "protocol:                       %s\n", my.protocol?"HTTP/1.1":"HTTP/1.0" );
  if(my.proxy.required){
    printf("proxy-host:                     %s\n", my.proxy.hostname);
    printf("proxy-port:                     %d\n", my.proxy.port);
  }
  printf( "connection:                     %s\n", my.keepalive?"keep-alive":"close" );
  printf( "concurrent users:               %d\n", my.cusers );
  if( my.secs > 0 )
    printf( "time to run:                    %d seconds\n", my.secs );
  else
    printf( "time to run:                    n/a\n" );
  if(( my.reps > 0 )&&( my.reps != MAXREPS ))
    printf( "repetitions:                    %d\n", my.reps );
  else
    printf( "repetitions:                    n/a\n" );
  printf( "socket timeout:                 %d\n", my.timeout );
  printf( "delay:                          %d sec%s\n", my.delay,my.delay>1?"s":"" );
  printf( "internet simulation:            %s\n", my.internet?"true":"false"  );
  printf( "benchmark mode:                 %s\n", my.bench?"true":"false"  );
  printf( "failures until abort:           %d\n", my.failures );
  printf( "named URL:                      %s\n", my.url==NULL||strlen(my.url)<2?"none":my.url );
  printf( "URLs file:                      %s\n", strlen(my.file)>1?my.file:URL_FILE );
  printf( "logging:                        %s\n", my.logging?"true":"false" );
  printf( "log file:                       %s\n", my.logfile==NULL?LOG_FILE:my.logfile );
  printf( "resource file:                  %s\n", my.rc);
  printf( "allow redirects:                %s\n", my.follow?"true":"false" );
  printf( "allow zero byte data:           %s\n", my.zero_ok?"true":"false" ); 
  printf( "allow chunked encoding:         %s\n", my.chunked?"true":"false" ); 
  printf( "proxy auth:                     " ); display_authorization( PROXY );printf( "\n" );
  printf( "www auth:                       " ); display_authorization( WWW ); 
  printf( "\n" );

  if( EXIT ) exit(0);
  else return 0;
}

static char
*get_line(FILE *fp)
{
  char *ptr = NULL;
  char *newline;
  char tmp[256];

  memset( tmp, 0, sizeof(tmp)); 
  do {
    if((fgets(tmp, sizeof(tmp), fp)) == NULL) return(NULL);
    if(ptr == NULL) {
      ptr = xstrdup( tmp );
    } else {
      ptr = (char*)xrealloc(ptr, strlen(ptr) + strlen(tmp) + 1);
      strcat( ptr, tmp );
    }
    newline = strchr(ptr, '\n');
  } while( newline == NULL );
  *newline = '\0';
 
  return ptr;
} 

static char
*chomp_line(FILE *fp, char **mystr, int *line_num)
{
  char *ptr;
  while(TRUE){
    if((*mystr = get_line( fp )) == NULL) return NULL;
    (*line_num)++;
    ptr = chomp(*mystr);
    /* exclude comments */
    if(*ptr != '#' && *ptr != '\0'){
      return(ptr);
    } else {
      xfree(ptr);
    }
  }
} 

int
load_conf(char *filename)
{
  FILE *fp;
  HASH H;
  int  line_num = 0;
  char *line;
  char *tmp;
  char *option;
  char *optionptr;
  char *value;
 
  if ((fp = fopen(filename, "r")) == NULL) {
    return -1;
  } 

  H = new_hash(16);

  while((line = chomp_line(fp, &line, &line_num)) != NULL){
    tmp    = line;
    optionptr = option = xstrdup(line);
    while(*optionptr && !ISSPACE((int)*optionptr) && !ISSEPARATOR(*optionptr))
      optionptr++;
    *optionptr++=0;
    while(ISSPACE((int)*optionptr) || ISSEPARATOR(*optionptr))
      optionptr++;
    value  = xstrdup(optionptr);
    while(*line)
      line++;  
    while(strstr(option, "$")){
      option = evaluate(H, option);
    }
    while(strstr(value, "$")){
      value = evaluate(H, value);
    } 
    if(strmatch(option, "verbose")){
      if(!strncasecmp(value, "true", 4))
        my.verbose = TRUE;
      else
        my.verbose = FALSE;
    } 
    else if(strmatch(option, "csv")){
      if(!strncasecmp(value, "true", 4))
        my.csv = TRUE;
      else
        my.csv = FALSE;
    } 
    else if(strmatch(option, "fullurl")){
      if(!strncasecmp(value, "true", 4))
        my.fullurl = TRUE;
      else
        my.fullurl = FALSE;
    } 
    else if(strmatch(option, "display-id")){
      if(!strncasecmp(value, "true", 4))
        my.display = TRUE;
      else
        my.display = FALSE;
    } 
    else if(strmatch( option, "logging")){
      if(!strncasecmp( value, "true", 4))
        my.logging = TRUE;
      else
        my.logging = FALSE;
    }
    else if(strmatch(option, "show-logfile")){
      if(!strncasecmp(value, "true", 4))
        my.shlog = TRUE;
      else
        my.shlog = FALSE;
    }
    else if(strmatch(option, "logfile")){
      strncpy(my.logfile, value, sizeof(my.logfile)); 
    } 
    else if(strmatch(option, "cookies")){
      if(strmatch(value, "true"))
        my.cookies = TRUE;
      else
        my.cookies = FALSE;
    }
    else if(strmatch(option, "concurrent")){
      if(value != NULL){
        my.cusers = atoi(value);
      } else {
        my.cusers = 10;
      }
    } 
    else if(strmatch(option, "reps")){
      if(value != NULL){
        my.reps = atoi(value);
      } else {
        my.reps = 5;
      }
    }
    else if(strmatch(option, "time")){
      parse_time(value);
    }
    else if(strmatch(option, "delay")){
      if(value != NULL){
        my.delay = atoi(value);
      } else {
        my.delay = 1;
      }
    }
    else if(strmatch(option, "timeout")){
      if(value != NULL){
        my.timeout = atoi(value);
      } else {
        my.timeout = 15;
      }
    }
    else if(strmatch(option, "internet")){
      if(!strncasecmp(value, "true", 4))
        my.internet = TRUE;
      else
        my.internet = FALSE;
    }
    else if(strmatch(option, "benchmark")){
      if(!strncasecmp(value, "true", 4)) 
        my.bench = TRUE;
      else
        my.bench = FALSE;
    }
    else if(strmatch(option, "cache")){
      if(!strncasecmp(value, "true", 4)) 
        my.cache = TRUE;
      else
        my.cache = FALSE;
    }
    else if(strmatch( option, "debug")){
      if(!strncasecmp( value, "true", 4))
        my.debug = TRUE;
      else
        my.debug = FALSE;
    }
    else if(strmatch(option, "file")){
      memset(my.file, 0, sizeof(my.file));
      strncpy(my.file, value, sizeof(my.file));
    }
    else if(strmatch(option, "url")){
      my.url = stralloc(value);
    }
    else if(strmatch(option, "user-agent")){
      strncpy(my.uagent, value, sizeof(my.uagent));
    }
    else if(strmatch(option, "accept-encoding")){
      strncpy(my.encoding, value, sizeof(my.encoding));
    }
    else if(!strncasecmp(option, "login", 5)){
      if(strmatch(option, "login-url")){  
        /* login URL */
        my.login = TRUE;
        my.loginurl = stralloc(value);
      } else {
        /* user login info */
        char *usr, *pwd, *rlm, *tmpvalue;
        usr = tmpvalue = value;
        while( *tmpvalue && *tmpvalue != ':' && *tmpvalue != '\0' )
          tmpvalue++;
        *tmpvalue++=0; pwd = tmpvalue;
        while( *tmpvalue && *tmpvalue != ':' && *tmpvalue != '\0' )
	  tmpvalue++;
	if('\0' != *tmpvalue) {
	  *tmpvalue++=0;
	  rlm = tmpvalue;
	} else {
	  rlm = NULL;
	}
        add_authorization(WWW, usr, pwd, rlm);
      }
    }
    else if(strmatch(option, "attempts")){
      if(value != NULL){
        my.bids = atoi(value);
      } else { 
        my.bids = 3;
      }
    }
    else if(strmatch(option, "username")){
      my.username = stralloc(trim(value));
    }
    else if(strmatch(option, "password")){
      my.password = stralloc(trim(value));
    }
    else if(strmatch(option, "connection")){
      if(!strncasecmp(value, "keep-alive", 10))
        my.keepalive = TRUE;
      else
        my.keepalive = FALSE; 
    }
    else if(strmatch(option, "protocol")){
      if(!strncasecmp(value, "HTTP/1.1", 8))
        my.protocol = TRUE;
      else
        my.protocol = FALSE; 
    }
    else if(strmatch(option, "proxy-host")){
      my.proxy.hostname = xstrdup(trim(value));
    }
    else if(strmatch(option, "proxy-port")){
      if(value != NULL){
        my.proxy.port = atoi(value);
      } else {
        my.proxy.port = 3128;
      }
    } 
    else if(strmatch(option, "proxy-login")){
      char *usr, *pwd, *rlm, *tmpvalue;
      usr = tmpvalue = value;
      while(*tmpvalue && *tmpvalue != ':' && *tmpvalue != '\0')
        tmpvalue++;
      *tmpvalue++=0; pwd = tmpvalue;
      while(*tmpvalue && *tmpvalue != ':' && *tmpvalue != '\0')
      tmpvalue++;
      if('\0' != *tmpvalue) {
	*tmpvalue++=0;
	rlm = tmpvalue;
      } else {
        rlm = NULL;
      }
      add_authorization(PROXY, usr, pwd, rlm);  
    }
    else if(strmatch(option, "failures")){
      if(value != NULL){
        my.failures = atoi(value);
      } else {
        my.failures = 30;
      }
    }
    else if(strmatch(option, "chunked")){
      if(!strncasecmp(value, "true", 4))
        my.chunked = TRUE;
      else
        my.chunked = FALSE;  
    }
    else if(strmatch(option, "header")){
      if(!strchr(value,':')) NOTIFY(FATAL, "no ':' in http-header");
      if((strlen(value) + strlen(my.extra) + 3) > 512) NOTIFY(FATAL, "too many headers");
      strcat(my.extra,value);
      strcat(my.extra,"\015\012");
    }
    else if(strmatch(option, "expire-session")){
      if (!strncasecmp(value, "true", 4 ))
        my.expire = TRUE;
      else
        my.expire = FALSE;
    }
    else if(strmatch(option, "follow-location")){
      if ( !strncasecmp( value, "true", 4 ))
        my.follow = TRUE;
      else
        my.follow = FALSE;
    }
    else if(strmatch(option, "zero-data-ok")){
      if( !strncasecmp(value, "true", 4))
        my.zero_ok = TRUE;
      else
        my.zero_ok = FALSE;
    } 
    else if(strmatch(option, "ssl-cert")){
      my.ssl_cert = stralloc(value);
    }
    else if(strmatch(option, "ssl-key")){
      my.ssl_key = stralloc(value);
    }
    else if(strmatch(option, "ssl-timeout")){
      if(value != NULL){
        my.ssl_timeout = atoi(value);
      } else {
        my.ssl_timeout = 15;
      }
    }
    else if(strmatch(option, "ssl-ciphers")){
      my.ssl_ciphers = stralloc(value);
    } 
    else if(strmatch(option, "spinner")){
      if(!strncasecmp(value, "true", 4))
        my.spinner = TRUE;
      else
        my.spinner = FALSE;
    } else {
      hash_add(H, option, value);
    }
    xfree(value);
    xfree(option);
    free(tmp);
  } /* end of while line=chomp_line */

  hash_destroy(H);
  fclose(fp);
  return 0;
}

/**
 * don't be insulted, the author is the 
 * DS Module in question...   ;-)
 */ 
void
ds_module_check( void )
{
  if( my.bench ){ 
#if defined(hpux) || defined(__hpux)
    my.delay = 1; 
#else
    my.delay = 0; 
#endif
  }
  if( my.secs > 0 && (( my.reps > 0 ) && ( my.reps != MAXREPS ))){
    NOTIFY(ERROR, "CONFIG conflict: selected time and repetition based testing" );
    fprintf( stderr, "defaulting to time-based testing: %d seconds\n", my.secs );
    my.reps = MAXREPS;
  }
}

