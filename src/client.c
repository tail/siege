/**
 * HTTP/HTTPS client support
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
#include <setup.h>
#include <client.h>
#include <signal.h>
#include <sock.h>
#include <ssl.h>
#include <http.h>
#include <url.h>
#include <util.h>
#include <auth.h>
#include <cookie.h>
#include <joedog/boolean.h>
#include <joedog/defs.h>

#if defined(hpux) || defined(__hpux) || defined(WINDOWS)
#define SIGNAL_CLIENT_PLATFORM
#endif

/**
 * local prototypes
 */
private BOOLEAN http_request(CONN *C, URL *U, CLIENT *c);
private void increment_failures();

#ifdef  SIGNAL_CLIENT_PLATFORM
static void signal_handler( int i );
static void signal_init();
#else /*CANCEL_CLIENT_PLATFORM*/
void clean_up();
#endif/*SIGNAL_CLIENT_PLATFORM*/
 
/**
 * local variables
 */
#ifdef SIGNAL_CLIENT_PLATFORM
static pthread_once_t once = PTHREAD_ONCE_INIT;
#endif/*SIGNAL_CLIENT_PLATFORM*/
float highmark = 0;
float lowmark = -1;  

/**
 * The thread entry point for clients.
 *
 * #ifdef SIGNAL_CLIENT_PLATFORM
 * the thread entry point for signal friendly clients.
 * (currently only HP-UX and Windows)
 *
 * #ifndef SIGNAL_CLIENT_PLATFORM
 * assume cancel client.
 * thread entry point for cancellable friendly operating systems like
 * aix, GNU/linux, solaris, bsd, etc.
 */
void *
start_routine(CLIENT *client)
{
  int x, y;                   /* loop counters, indices    */
  int ret;                    /* function return value     */
  CONN *C = NULL;             /* connection data (sock.h)  */ 
#ifdef SIGNAL_CLIENT_PLATFORM
  sigset_t  sigs;
#else
  int type, state;
#endif 

  C = xcalloc(sizeof(CONN), 1);
  C->sock = -1;

#ifdef SIGNAL_CLIENT_PLATFORM
  pthread_once(&once, signal_init);
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGUSR1);
  pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);
#else
  #if defined(_AIX)
    pthread_cleanup_push((void(*)(void*))clean_up, NULL);
  #else
    pthread_cleanup_push((void*)clean_up, C);
  #endif
#endif /*SIGNAL_CLIENT_PLATFORM*/

#ifdef SIGNAL_CLIENT_PLATFORM
#else/*CANCEL_CLIENT_PLATFORM*/
  #if defined(sun)
    pthread_setcanceltype (PTHREAD_CANCEL_DEFERRED, &type);
  #elif defined(_AIX)
    pthread_setcanceltype (PTHREAD_CANCEL_DEFERRED, &type);
  #elif defined(hpux) || defined(__hpux)
    pthread_setcanceltype (PTHREAD_CANCEL_ASYNCHRONOUS, &type);
  #else
    pthread_setcanceltype (PTHREAD_CANCEL_ASYNCHRONOUS, &type);
  #endif
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &state);
#endif/*SIGNAL_CLIENT_PLATFORM*/ 
  if(my.login == TRUE){
    http_request(C, add_url(my.loginurl, 0), client);
  }

  for( x = 0, y = 0; x < my.reps; x++, y++ ){
    x = (( my.secs > 0 ) && (( my.reps <= 0 )||( my.reps == MAXREPS))) ? 0 : x;
    if( my.internet == TRUE ){
      y = (unsigned int) (((double)pthread_rand_np(&(client->rand_r_SEED)) /
                          ((double)RAND_MAX + 1) * my.length ) + .5); 
      y = (y >= my.length)?my.length-1:y;
      y = (y < 0)?0:y;
    } else {
      /**
       * URLs accessed sequentially; when reaching the end, start over
       * with clean slate, ie. reset (delete) cookies (eg. to let a new
       * session start)
       */
      if( y >= my.length ){
        y = 0;
        if( my.expire ){
          delete_all_cookies(pthread_self());
        }
      }
    }
    if(y >= my.length || y < 0){ 
      printf("y out of bounds: %d >= %d", y, my.length); 
      y = 0; 
    }

    if(client->U[y] != NULL && client->U[y]->hostname != NULL){
      client->auth.bids.www = 0; /* reset */
      if((ret = http_request(C, client->U[y], client))==FALSE){
        increment_failures();
      }
    }
 
    if(my.failures > 0 && my.failed >= my.failures){
      break;
    }
  }

  #ifdef SIGNAL_CLIENT_PLATFORM
  #else/*CANCEL_CLIENT_PLATFORM*/
  /**
   * every cleanup must have a pop
   */
  pthread_cleanup_pop(0);
  #endif/*SIGNAL_CLIENT_PLATFORM*/ 
  if(C->sock >= 0){
    C->connection.reuse = 0;    
    socket_close(C);
  }
  xfree(C);
  C = NULL;

  return(NULL);
}

/**
 * this function is common to the two client functions
 * above. This invokes the HTTP logic and compiles the
 * statistics for the run.
 */
private BOOLEAN
http_request(CONN *C, URL *U, CLIENT *client)
{
  unsigned long bytes  = 0;
  int      code, fail;  
  float    etime; 
  clock_t  start, stop;
  struct   tms t_start, t_stop; 
  HEADERS  *head; 
#ifdef  HAVE_LOCALTIME_R
  struct   tm keepsake;
#endif/*HAVE_LOCALTIME_R*/
  time_t   now; 
  struct   tm *tmp;
  size_t   len;
  char     fmtime[65];


  if(my.csv){
    now = time(NULL);
#ifdef HAVE_LOCALTIME_R
    tmp = (struct tm *)localtime_r(&now, &keepsake);
#else
    tmp = localtime(&now);
#endif/*HAVE_LOCALTIME_R*/
    if(tmp)
      len = strftime(fmtime, 64, "%Y-%m-%d %H:%M:%S", tmp);
    else
      snprintf(fmtime, 64, "n/a");
  }

  C->pos_ini              = 0;
  C->inbuffer             = 0; 
  C->content.transfer     = NONE;
  C->content.length       = 0;
  C->connection.keepalive = (C->connection.max==1)?0:my.keepalive;
  C->connection.reuse     = (C->connection.max==1)?0:my.keepalive;
  C->connection.tested    = (C->connection.tested==0)?1:C->connection.tested; 
  C->auth.www             = client->auth.www;
  C->auth.wwwchlg         = client->auth.wwwchlg;
  C->auth.wwwcred         = client->auth.wwwcred;
  C->auth.proxy           = client->auth.proxy;
  C->auth.proxychlg       = client->auth.proxychlg;
  C->auth.proxycred       = client->auth.proxycred;
  C->auth.type.www        = client->auth.type.www;
  C->auth.type.proxy      = client->auth.type.proxy;
  memset(C->buffer, 0, sizeof(C->buffer));

  if(U->protocol == UNSUPPORTED){ 
    if(my.verbose && !my.get){
      printf(
        "%s %d %6.2f secs: %7d bytes ==> %s\n",
        "UNSPPRTD", 501, 0.00, 0, "PROTOCOL NOT SUPPORTED BY SIEGE" 
      );
    } /* end if my.verbose */
    return FALSE;
  }

  if(my.delay){
    pthread_sleep_np(
     (unsigned int) (((double)pthread_rand_np(&(client->rand_r_SEED)) /
                     ((double)RAND_MAX + 1) * my.delay ) + .5) 
    );
  }

  C->prot = U->protocol;

  /* record transaction start time */
  start = times(&t_start);  

  debug( 
    "attempting connection to %s:%d\n", 
    (my.proxy.required==TRUE)?my.proxy.hostname:U->hostname,
    (my.proxy.required==TRUE)?my.proxy.port:U->port 
  ); 

  if(!C->connection.reuse || C->connection.status == 0){
    if(my.proxy.required){
      debug("client.c:%d new_socket: %s:%d", __LINE__, my.proxy.hostname, my.proxy.port); 
      C->sock = new_socket(C, my.proxy.hostname, my.proxy.port);
    } else {
      debug("client.c:%d new_socket: %s:%d", __LINE__, U->hostname, U->port); 
      C->sock = new_socket(C, U->hostname, U->port);
    }
  }

  if(my.keepalive){
    C->connection.reuse = TRUE;
  }

  if(C->sock < 0){
    debug(
      "connection failed. erro %d(%s)",errno,strerror(errno)
    ); 
    socket_close(C);
    return FALSE;
  } 

  debug("%s:%d connection made: %d", __FILE__, __LINE__, C->sock); 

  if(C->prot == HTTPS){
    if(my.proxy.required){
      https_tunnel_request(C, U->hostname, U->port);
      https_tunnel_response(C);
    }
    C->encrypt = TRUE;
    if(SSL_initialize(C)==FALSE){
      return FALSE;
    }
  }

  /**
   * write to socket with a POST or GET
   */
  if(U->calltype == URL_POST){ 
    if((http_post(C, U)) < 0){
      C->connection.reuse = 0;
      socket_close(C);
      return FALSE;
    }
  } else { 
    if((http_get(C, U)) < 0){
      C->connection.reuse = 0;
      socket_close(C);
      return FALSE;
    }
  } 
  /**
   * read from socket and collect statistics.
   */
  if((head = http_read_headers(C, U))==NULL){
    C->connection.reuse = 0; 
    socket_close(C); 
    debug("NULL headers: %s:%d", __FILE__, __LINE__);
    return FALSE; 
  }

  bytes = http_read(C); 

  if(!my.zero_ok && (bytes < 1)){ 
    C->connection.reuse = 0; 
    socket_close(C); 
    http_free_headers(head); 
    debug("zero bytes %s:%d", __FILE__, __LINE__);
    return FALSE; 
  } 
  stop     =  times(&t_stop); 
  etime    =  elapsed_time(stop - start);  
  code     =  (head->code <  400 || head->code == 401 || head->code == 407) ? 1 : 0;
  fail     =  (head->code >= 400 && head->code != 401 && head->code != 407) ? 1 : 0; 
  /**
   * quantify the statistics for this client.
   */
  client->bytes += bytes;
  client->time  += etime;
  client->code  += code;
  client->fail  += fail;
  if(head->code == 200){
    client->ok200++;
  }

  /**
   * check to see if this transaction is the longest or shortest
   */
  if (etime > highmark) {
    highmark = etime;
  }
  if ( ( lowmark < 0 ) || ( etime < lowmark ) ) {
    lowmark = etime;
  }
  client->bigtime = highmark;
  client->smalltime = lowmark;

  /**
   * verbose output, print statistics to stdout
   */
  if((my.verbose && !my.get) && (!my.debug)){
    if(my.csv){
      if(my.display)
        printf("%s%s%4d,%s,%d,%6.2f,%7lu,%s,%d,%s\n",
        (my.mark)?my.markstr:"", (my.mark)?",":"", client->id, head->head, head->code, 
        etime, bytes, (my.fullurl)?U->url:U->pathname, U->urlid, fmtime
      );
      else
        printf("%s%s%s,%d,%6.2f,%7lu,%s,%d,%s\n",
          (my.mark)?my.markstr:"", (my.mark)?",":"", head->head, head->code, 
          etime, bytes, (my.fullurl)?U->url:U->pathname, U->urlid, fmtime
        );
    } else {
      if(my.display)
        printf(
          "%4d: %s %d %6.2f secs: %7lu bytes ==> %s\n", client->id,
          head->head, head->code, etime, bytes, (my.fullurl)?U->url:U->pathname
        ); 
      else
        printf( 
          "%s %d %6.2f secs: %7lu bytes ==> %s\n", 
          head->head, head->code, etime, bytes, (my.fullurl)?U->url:U->pathname
        );
    } /* else not my.csv */
  }

  /**
   * close the socket and free memory.
   */
  if(!my.keepalive){
    socket_close(C);
  }
 
  /**
   * deal with HTTP > 300 
   */
  switch(head->code){
    URL  *redirect_url; /* URL in redirection request */
    case 301:
    case 302:
      redirect_url = (URL*)xmalloc(sizeof(URL));
      if(my.follow && head->redirect[0]){
        debug("parsing redirection URL %s", head->redirect);
        if(protocol_length(head->redirect) == 0){
          memcpy(redirect_url, U, sizeof(URL));
          redirect_url->pathname = head->redirect;
        } else {
          redirect_url = add_url(head->redirect, U->urlid);
        }
        if((http_request(C, redirect_url, client)) == FALSE)
          return FALSE;
      }
      xfree(redirect_url);
      break;
    case 401:
      /**
       * WWW-Authenticate challenge from the WWW server
       */
      client->auth.www = (client->auth.www==0)?1:client->auth.www;
      if((client->auth.bids.www++) < my.bids - 1){
        if(head->auth.type.www == DIGEST){
          client->auth.type.www = DIGEST;
	  if(set_digest_authorization(WWW, &(client->auth.wwwchlg), &(client->auth.wwwcred), &(client->rand_r_SEED), head->auth.realm.www, head->auth.challenge.www) < 0) {
	    fprintf(stderr, "ERROR from set_digest_authorization\n");
	    return FALSE;
	  }
          break; 
        }
        if(head->auth.type.www == BASIC){
          client->auth.type.www =  BASIC;
          set_authorization(WWW, head->auth.realm.www);
        }
        if((http_request(C, U, client)) == FALSE){
          fprintf(stderr, "ERROR from http_request\n");
          return FALSE;
        }
      }
      break;
    case 407:
      /**
       * Proxy-Authenticate challenge from the proxy server.
       */
      client->auth.proxy = (client->auth.proxy==0)?1:client->auth.proxy;
      if((client->auth.bids.proxy++) < my.bids - 1){
        if(head->auth.type.proxy == DIGEST){
          client->auth.type.proxy =  DIGEST;
	  if(set_digest_authorization(PROXY, &(client->auth.proxychlg), &(client->auth.proxycred), &(client->rand_r_SEED), head->auth.realm.proxy, head->auth.challenge.proxy) < 0) {
	    fprintf(stderr, "ERROR from set_digest_authorization\n");
	    return FALSE;
	  } 
          break;
        }
        if(head->auth.type.proxy == BASIC){
          client->auth.type.proxy = BASIC;
          set_authorization(PROXY, head->auth.realm.proxy);
        }
        if((http_request(C, U, client)) == FALSE)
          return FALSE;
      }
      break;
    case 500:
    case 501:
    case 502:
    case 503: 
    case 504: 
    case 505:
    case 506:
    case 507:
    case 508:
    case 509:
      return FALSE;
    default:
      break;
  }

  client->hits  ++; 
  http_free_headers(head);

  return TRUE;
}

#ifdef SIGNAL_CLIENT_PLATFORM
private void
signal_handler(int sig)
{
  pthread_exit(&sig);
}
 
private void
signal_init()
{
  struct sigaction sa;
 
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGUSR1, &sa, NULL);
}
#else/*CANCEL_CLIENT_PLATFORM*/

void
clean_up()
{
  return;
}
#endif

private void
increment_failures()
{
  pthread_mutex_lock(&(my.lock));  
  my.failed++;
  pthread_mutex_unlock(&(my.lock));  
  pthread_testcancel();
}

