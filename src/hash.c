/**
 * Hash Table
 *
 * Copyright (C) 2003-2007 by
 * Jeffrey Fulmer - <jeff@joedog.org>, et al. 
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
#include <string.h>
#include <stdlib.h>
#include <hash.h>
#include <joedog/joedog.h>

typedef struct NODE
{
  char  *key;
  char  *value;
  struct NODE *next;
} NODE;

struct HASH_T
{
  int   size;
  int   entries;
  int   index;
  NODE  **table;
};

/** 
 * local prototypes
 */
int  hash_lookup(HASH this, char *key);
static void hash_resize( HASH this ); 

/**
 * returns int hash key for the table
 */
int
hash_genkey( int size, char *str )
{
  return ((int)(*str)) % size;
}

/**
 * allocs size and space for the 
 * hash table. 
 */
HASH 
new_hash( ssize_t size )
{
  HASH this;

  this = calloc(sizeof(*this),1);
  this->size    = 2;
  this->entries = 0;
  this->index   = 0;
  while( this->size < size ){
    this->size <<= 1;
  }
  this->table = (NODE**)calloc(this->size * sizeof(NODE*), 1);
  return this;
}

void
hash_reset(HASH this, ssize_t size )
{
  this->size    = 2;
  this->entries = 0;

  while( this->size < size ){
    this->size <<= 1;
  }

  this->table = (NODE**)calloc(this->size * sizeof(NODE*), 1);
  return;
}

/**
 * redoubles the size of the hash table. 
 * This is a local function called by hash_add 
 * which dynamically resizes the table as 
 * necessary.
 */
static void
hash_resize( HASH this ) 
{
  NODE *tmp;
  NODE *last_node; 
  NODE **last_table;
  int  x, hash, size;
 
  size        = this->size; 
  last_table = this->table;

  hash_reset(this, size*2);

  x = 0;
  while( x < size ){
    last_node = last_table[x]; 
    while( last_node != NULL ){
      tmp       = last_node;
      last_node = last_node->next;
      hash      = hash_genkey( this->size, (char*)tmp->key );
      tmp->next = this->table[hash];
      this->table[hash] = tmp;
      this->entries++;
    } 
    x++;
  } 
  return;
}

/**
 * add a key value pair to the hash table.
 * This function tests the size of the table
 * and dynamically resizes it as necessary.
 * len is the size of void pointer.
 */
void
hash_add( HASH this, char *key, char *value )
{
  int  x;
  NODE *node;

  if( hash_lookup(this, key) == 1 )
    return;

  if( this->entries >= this->size/2 )
    hash_resize( this );

  x = hash_genkey(this->size, key);
  node        = xmalloc(sizeof(NODE));
  node->key   = strdup(key);
  node->value = strdup(value);
  node->next  = this->table[x]; 
  this->table[x] = node;
  this->entries++;
  return;
}

/**
 * returns a void NODE->value element
 * in the table corresponding to key.
 */
char *
hash_get(HASH this, char *key)
{
  int  x;
  NODE *node;

  x = hash_genkey(this->size, key);
  for(node = this->table[x]; node != NULL; node = node->next){
    if(!strcmp( node->key, key)){
      return(node->value);
    }
  }

 return NULL;
} 

/**
 * returns 1 if key is present in the table
 * and 0 if it is not.
 */
int
hash_lookup(HASH this, char *key)
{
  int  x;
  NODE *node;

  if (key == NULL) { return 1; }
  x = hash_genkey(this->size, key);
  for(node = this->table[x]; node != NULL; node = node->next){
    if(!strcmp(node->key, key)){
      return 1;
    }
  }

 return 0;
}

char **
hash_get_keys(HASH this)
{
  int x; 
  int i = 0;
  NODE *node;
  char **keys;

  keys = (char**)malloc(sizeof( char*) * this->entries);
  for(x = 0; x < this->size; x ++){
    for(node = this->table[x]; node != NULL; node = node->next){
      keys[i] = (char*)malloc(128);
      memset( keys[i], 0, sizeof(keys[i]));
      memcpy( keys[i], (char*)node->key, strlen(node->key));
      keys[i][strlen(node->key)] = 0;
      i++;
    }
  }
  return keys;
}

void 
hash_free_keys(HASH this, char **keys)
{
  int x;
  for(x = 0; x < this->entries; x ++)
    if(keys[x] != NULL){
      char *tmp = keys[x];
      xfree(tmp);
    }
  xfree(keys);

  return;
}

/**
 * destroy the hash table and free
 * memory which was allocated to it.
 */
void 
hash_destroy(HASH this)
{
  int x;
  NODE *t1, *t2;

  for(x = 0; x < this->size; x++){
    t1 = this->table[x];
    while(t1 != NULL){
      t2 = t1->next;
      if(t1->key != NULL)
        xfree(t1->key);
      if(t1->value != NULL)
        xfree(t1->value);
      xfree(t1);
      t1 = t2;      
    } 
    this->table[x] = NULL;
  }
  if(this->table != NULL){
    xfree(this->table);
    memset(this, 0, sizeof(HASH));
  } 
  xfree(this);
  return;
}

int
hash_get_entries(HASH this)
{
  return this->entries;
}

#if 0
int
main()
{
  HASH H = new_hash(4);
  int  x = 0;
  char **keys;


  hash_add(H, "homer", "whoo hoo");
  hash_add(H, "bart", "aye caramba");
  hash_add(H, "marge", "homey..."); 
  hash_add(H, "lisa", "in my room");
  hash_add(H, "cleatus", "young uns");
  hash_add(H, "burns", "excellent");
  hash_add(H, "nelson", "ah hah!");

  keys = hash_get_keys( H );
  for( x = 0; x < hash_get_entries(H); x ++ ){
    char *tmp = (char*)hash_get(H, keys[x]);
    printf("key: %s, value: %s\n", keys[x], (tmp==NULL)?"NULL":tmp);
  }
  hash_free_keys( H, keys );
  hash_destroy(H);
  exit( 0 ); 
}
#endif

