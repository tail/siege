#ifndef BOOLEAN_H
#define BOOLEAN_H 
 
typedef enum {boolean_false=0,boolean_true=1}                      BOOLEAN;
typedef enum {toolean_false=0,toolean_true=1,toolean_undefined=-1} TOOLEAN;
 
#ifndef  FALSE
# define FALSE     boolean_false
#endif /*FALSE*/

#ifndef  TRUE
# define TRUE      boolean_true
#endif /*TRUE*/

#ifndef  UNDEFINED
# define UNDEFINED toolean_undefined
#endif /*UNDEFINED*/
 
#endif/*BOOLEAN_H*/
