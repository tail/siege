#ifndef JOEDOG_DEFS_H
#define JOEDOG_DEFS_H
#define private static
#define public 

#define  ISSEPARATOR(x) (('='==(x))||(':'==(x)))
#define  ISSPACE(x)     isspace((unsigned char)(x))
#define  ISOPERAND(x) ('<'==(x)||'>'==(x)||'='==(x))
#define  ISDIGIT(x)     isdigit ((unsigned char)(x)) 
#define  ISQUOTE(x)   (x == '"' || x == '\'') 
#if STDC_HEADERS
# define TOLOWER(Ch) tolower (Ch)
# define TOUPPER(Ch) toupper (Ch)
#else
# define TOLOWER(Ch) (ISUPPER (Ch) ? tolower (Ch) : (Ch))
# define TOUPPER(Ch) (ISLOWER (Ch) ? toupper (Ch) : (Ch))
#endif

#ifndef  EXIT_SUCCESS
# define EXIT_SUCCESS   0
#endif /*EXIT_SUCESS*/
#ifndef  EXIT_FAILURE
# define EXIT_FAILURE   1
#endif /*EXIT_FAILURE*/ 

#endif/*JOEDOG_DEFS_H*/
