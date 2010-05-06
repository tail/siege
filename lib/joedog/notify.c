/**
 * Error notification
 * Library: joedog
 *
 * Copyright (C) 2000-2007 by
 * Jeffrey Fulmer - <jeff@joedog.org>, et. al.
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

#ifdef  HAVE_CONFIG_H
# include <config.h>
#endif/*HAVE_CONFIG_H*/

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <notify.h>

#define BUFSIZE 4096

typedef enum {
  __LOG = 1,
  __OUT = 2,
} METHOD;

static void __message(METHOD M, LEVEL L, const char *fmt, va_list ap);

void
OPENLOG(char *program)
{
  openlog(program, LOG_PID, LOG_DAEMON); 
  return;
}

void 
CLOSELOG(void)
{
  closelog();
  return;
}

static void
__message(METHOD M, LEVEL L, const char *fmt, va_list ap)
{
  char   buf[BUFSIZE/2];
  char   msg[BUFSIZE];
  LEVEL  level = WARNING;
  char   mode[16];
  memset(mode, '\0', 16);


  vsprintf(buf, fmt, ap);
  if(errno == 0 || errno == ENOSYS){
    snprintf(msg, sizeof msg, "%s\n", buf);
  } else {
    snprintf(msg, sizeof msg, "%s: %s\n", buf, strerror(errno));
  }

  switch(L){
    case WARNING:
      strcpy(mode, "[warning]");
      level = LOG_WARNING;
      break;
    case ERROR:
      strcpy(mode, "[error]  ");
      level = LOG_ERR;
      break;
    case FATAL:
      strcpy(mode, "[fatal]  ");
      level = LOG_CRIT;
      break;
  }
  
  if(M == __LOG){
    syslog(level, "%s %s", mode, msg);
  } else {
    fflush(stdout);
    fprintf(stderr, "%s %s", mode, msg);
  }
  if(L==FATAL){ exit(1); }
  return;
}

void 
SYSLOG(LEVEL L, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  
  __message(__LOG, L, fmt, ap);
  va_end(ap);
  
  return;
}

void
NOTIFY(LEVEL L, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);

  __message(__OUT, L, fmt, ap);
  va_end(ap);

  return;
}


