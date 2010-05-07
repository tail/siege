/**
 * Utility Functions
 *
 * Copyright (C) 2001-2007 
 * by Jeffrey Fulmer <jeff@joedog.org>, et al.
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
 *
 */
#ifndef  UTIL_H
#define  UTIL_H

#include <joedog/boolean.h>

void    parse_time(char *p);
void    pthread_sleep_np(unsigned int seconds); 
void    pthread_usleep_np(unsigned long usec); 
int     pthread_rand_np(unsigned int *ctx); 
BOOLEAN strmatch(char *str1, char *str2);
void    debug(const char *fmt, ...);
char    *uppercase(char *s, size_t len);
char    *lowercase(char *s, size_t len);
#ifndef strnlen
size_t  strnlen(const char *str, size_t len);
#endif
#ifndef strncasestr
char    *strncasestr(const char *str1, const char *str2, size_t len);
#endif

#endif /*UTIL_H*/

