#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <array.h>
#include <joedog/joedog.h>

struct ARRAY_T
{
  int   size;
  int   index;
  int   length;
  void  **data;
};


ARRAY
new_array(int size){
  ARRAY this;

  if(size < 1 || size > INT_MAX) return NULL;
 
  this = xcalloc(sizeof(*this), 1);
  this->size   = size;
  this->index  = -1;
  this->length = 0;
  this->data   = xmalloc(size * sizeof(char*)); 
  return this;
}

ARRAY
array_destroy(ARRAY this) 
{
  int i;

  for (i = 0; i < this->size; i++) {
    xfree(this->data[i]);  
  } 
  xfree(this->data);
  this = NULL;
  return this; 
}

void 
array_push(ARRAY this, void *thing)
{
  int len = 0;

  if (thing==NULL) return;

  len = strlen(thing)+1;
  array_npush(this, (void*)thing, len);
  return;
}

void
array_npush(ARRAY this, void *thing, size_t len) 
{
  if (thing==NULL) return;
  if (this->length == this->size) return;
  this->data[this->length] = xmalloc(len);
  memset(this->data[this->length], 0, len);
  memcpy(this->data[this->length], thing, len);
  this->length += 1;
  return;
}

void *
array_get(ARRAY this, int index)
{
  if (index > this->length) return NULL;

  return this->data[index];
}

void *
array_next(ARRAY this) 
{
  this->index++;
  return this->data[(this->index) % this->length]; 
}

void *
array_prev(ARRAY this) 
{
  this->index--;
  return this->data[((this->index) + (this->length - 1)) % this->length] ;  
}

size_t
array_length(ARRAY this)
{
  return this->length; 
}

#if 0
int
main (int argc, char *argv[])
{
  int   x;
  ARRAY A = new_array(30);

  if (argc > 1) {
    for (x = 1; x < argc; x++)
      array_npush(A, new_url(argv[x]), sizeof(struct _URL));
  } else {
    printf("usage: %s <url> [...]\n", argv[0]);
    return 0;
  }

  for (x = 0; x < 10; x++) {
    URL U = (URL)array_next(A);
    printf("|%s|\n",  U->iface->getParameters(U) );
  }
  //for (x = 0; x < 10; x++) {
  //  printf("|%s|\n", ((char*)array_prev(A)));
  //}

  return 0;
}
#endif
