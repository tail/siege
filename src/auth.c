#include <stdio.h>
#include <stdlib.h>
#include <auth.h>
#include <base64.h> 
#include <md5.h>
#include <setup.h>
#include <util.h>
#include <joedog/joedog.h> 

void
add_authorization(SERVICE service, char *username, char *password, char *realm)
{
  struct LOGIN *tail = NULL;

  tail = (struct LOGIN*)xmalloc(sizeof(struct LOGIN));
  tail->username = xstrdup(username);
  tail->password = xstrdup(password);
  tail->realm    = (realm!=NULL&&strlen(realm)>1)?xstrdup( realm ):xstrdup("all");
  switch(service){
  case WWW:
    tail->next   = my.auth.head;
    my.auth.head = tail;
    break;
  case PROXY:
    tail->next   = my.proxy.head;
    my.proxy.head= tail;
    break;
  default:
    break;
  }
  return;
} 

int
display_authorization(SERVICE service)
{
  struct LOGIN *li = (service==WWW)?my.auth.head:my.proxy.head;

  while(li != NULL){
    printf("%s:%s [%s]\n", li->username, li->password, li->realm);
    li = li->next; 
  }
  return 0;
}

int
set_authorization(SERVICE service, char *realm) 
{
  char buf[64];
  struct LOGIN *li     = (service==WWW)?my.auth.head:my.proxy.head;
  pthread_mutex_t lock = (service==WWW)?my.auth.lock:my.proxy.lock;
 
  while(li != NULL){
    if(!strncasecmp(li->realm, realm, strlen(realm))){ 
      pthread_mutex_lock(&(lock)); 
      snprintf( 
        buf, sizeof(buf), 
        "%s:%s", 
        (li->username!=NULL)?li->username:"", (li->password!=NULL)?li->password:"" 
      ); 
      if(service==WWW){
	xfree(my.auth.encode);
        if(( base64_encode(buf, strlen(buf), &my.auth.encode) < 0 ))
          return -1;
      } else {
	xfree(my.proxy.encode);
        if((base64_encode(buf, strlen(buf), &my.proxy.encode) < 0))
          return -1;
      }
      pthread_mutex_unlock(&(lock)); 
      return 0;
    } 
    li = li->next;
  }
  /* failed to match, attempting default */
  li = (service==WWW)?my.auth.head:my.proxy.head; 
  if(li == NULL)
    return -1;
  pthread_mutex_lock(&(lock));
  snprintf(
    buf, sizeof buf,
    "%s:%s",
    (li->username!=NULL)?li->username:"", (li->password!=NULL)?li->password:""
  ); 
  if(service==WWW){
    xfree(my.auth.encode);
    if((base64_encode(buf, strlen(buf), &my.auth.encode) < 0))
      return -1;
  } else {
    xfree(my.proxy.encode);
    if(( base64_encode( buf, strlen(buf), &my.proxy.encode ) < 0 ))
      return -1;
  }
  pthread_mutex_unlock(&(lock));
  return 0;
}

/* Digest implementation starts here */
struct DIGEST_CRED
{
  char *username;
  char *password;
  char *cnonce_value;
  char *h_a1;
  char nc[9];
  unsigned int nc_value;
};

struct DIGEST_CHLG
{
 char *realm;
 char *domain;
 char *nonce;
 char *opaque;
 char *stale;
 char *algorithm;
 char *qop;
};

typedef enum
{
  REALM,
  DOMAIN,
  NONCE,
  OPAQUE,
  STALE,
  ALGORITHM,
  QOP,

  UNKNOWN
}
KEY_HEADER_E;

typedef struct
{
  const char *keyname;
  KEY_HEADER_E keyval;
} KEYPARSER;

static const KEYPARSER keyparser_array[] = {
  {"realm", REALM },
  {"domain", DOMAIN },
  {"nonce", NONCE },
  {"opaque", OPAQUE },
  {"stale", STALE },
  {"algorithm", ALGORITHM },
  {"qop", QOP },
  {NULL, UNKNOWN}
};

static KEY_HEADER_E
get_keyval(const char *key)
{
  int i;

  for(i = 0; keyparser_array[i].keyname; i++) {
    if(!strcasecmp(key, keyparser_array[i].keyname))
      return keyparser_array[i].keyval;
  }

  return UNKNOWN;
}

static DIGEST_CHLG *
digest_challenge_make(const char *challenge)
{
  DIGEST_CHLG *result;
  const char *beg, *end;
  char *key, *value;
  KEY_HEADER_E keyval;

  result = xcalloc(1, sizeof(struct DIGEST_CHLG));

  for (beg = end = challenge; !isspace(*end) && *end; ++end);

  if (strncasecmp("Digest", beg, end - beg)) {
    fprintf(stderr, "no Digest keyword in challenge [%s]\n", challenge);
    return NULL;
  }

  for (beg = end; isspace(*beg); ++beg);

  while (*beg != '\0') {

    /* find key */
    while (isspace(*beg))
      beg++;

    end = beg;
    while (*end != '=' && *end != ',' && *end != '\0' && !isspace(*end))
      end++;

    key = xmalloc((1 + end - beg) * sizeof(char));
    memcpy(key, beg, end - beg);
    key[end - beg] = '\0';

    beg = end;
    while (isspace(*beg))
      beg++;

    /* find value */
    value = NULL;
    if (*beg == '=') {
      beg++;
      while (isspace(*beg))
	beg++;

      if (*beg == '\"') {     /* quoted string */
	beg++;
	end = beg;
	while (*end != '\"' && *end != '\0') {
	  if (*end == '\\' && end[1] != '\0') {
	    end++;      /* escaped char */
	  }
	  end++;
	}
	value = xmalloc((1 + end - beg) * sizeof(char));
	memcpy(value, beg, end - beg);
	value[end - beg] = '\0';
	beg = end;
	if (*beg != '\0') {
	  beg++;
	}
      }
      else {              /* token */
	end = beg;
	while (*end != ',' && *end != '\0' && !isspace(*end))
	  end++;

	value = xmalloc((1 + end - beg) * sizeof(char));
	memcpy(value, beg, end - beg);
	value[end - beg] = '\0';
	beg = end;
      }
    }

    while (*beg != ',' && *beg != '\0')
      beg++;

    if (*beg != '\0') {
      beg++;
    }

    keyval = get_keyval(key);
    switch(keyval) {
      case REALM:
      result->realm = value;
      break;
      case DOMAIN:
      result->domain = value;
      break;
      case NONCE:
      result->nonce = value;
      break;
      case OPAQUE:
      result->opaque = value;
      break;
      case STALE:
      result->stale = value;
      break;
      case ALGORITHM:
      result->algorithm = value;
      break;
      case QOP:
      result->qop = value;
      break;
      default:
      fprintf(stderr, "unknown key [%s]\n", key);
      xfree(value);
      break;
    }
    xfree(key);
  }

  return result;
}

void
digest_challenge_destroy(DIGEST_CHLG *challenge)
{
  if(challenge != NULL){
    xfree(challenge->realm);
    xfree(challenge->domain);
    xfree(challenge->nonce);
    xfree(challenge->opaque);
    xfree(challenge->stale);
    xfree(challenge->algorithm);
    xfree(challenge->qop);
    xfree(challenge);
  }
}

static char *
get_random_string(size_t length, unsigned int *randseed)
{
  const unsigned char b64_alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./";
  unsigned char *result;
  size_t i;

  result = xmalloc(sizeof(unsigned char) * (length + 1));

  for(i = 0; i < length; i++)
    result[i] = (int) (255.0 * (pthread_rand_np(randseed) / (RAND_MAX + 1.0)));
  for (i = 0; i < length; i++)
    result[i] = b64_alphabet[(result[i] % ((sizeof(b64_alphabet) - 1) / sizeof(unsigned char)))];

  result[length] = '\0';

  return (char *) result;
}

#define DIGEST_CNONCE_SIZE 16

static DIGEST_CRED *
digest_credential_make(const char *username, const char *password, unsigned int *randseed)
{
  DIGEST_CRED *result;

  result = xcalloc(1, sizeof(struct DIGEST_CRED));
  result->username = xstrdup(username);
  result->password = xstrdup(password);
  /* Generate a pseudo random cnonce */
  result->cnonce_value = get_random_string(DIGEST_CNONCE_SIZE, randseed);
  result->nc_value = 1U;
  snprintf(result->nc, sizeof(result->nc), "%.8x", result->nc_value);
  result->h_a1 = NULL;

  return result;
}

void
digest_credential_destroy(DIGEST_CRED *credentials)
{
  if(credentials != NULL){
    xfree(credentials->username);
    xfree(credentials->password);
    xfree(credentials->cnonce_value);
    xfree(credentials->h_a1);
    xfree(credentials);
  }
}

int
set_digest_authorization(SERVICE service, DIGEST_CHLG **challenge, DIGEST_CRED **credentials, unsigned int *randseed, char *realm, char *str) 
{
  char buf[64];
  struct LOGIN *li     = (service==WWW)?my.auth.head:my.proxy.head;

  while(li != NULL){
    if(!strncasecmp(li->realm, realm, strlen(realm))){ 
      snprintf( 
	  buf, sizeof(buf), 
	  "%s:%s", 
	  (li->username!=NULL)?li->username:"", (li->password!=NULL)?li->password:"" 
	  ); 

      /**
       * XXX: need to add additional header info here
       */
      *challenge = digest_challenge_make(str);
      *credentials = digest_credential_make(li->username, li->password, randseed);
      if(*credentials == NULL || *challenge == NULL)
	return -1;

      return 0;
    }
    li = li->next;
  }
  /* failed to match, attempting default */
  li = (service==WWW)?my.auth.head:my.proxy.head; 
  if(li == NULL)
    return -1;
  snprintf(
      buf, sizeof( buf ),
      "%s:%s",
      (li->username!=NULL)?li->username:"", (li->password!=NULL)?li->password:""
      ); 

  *challenge = digest_challenge_make(str);
  *credentials = digest_credential_make(li->username, li->password, randseed);
  if(*credentials == NULL || *challenge == NULL)
    return -1;

  return 0;
}

static int
str_parse_list_has(const char *str, const char *pattern, size_t pattern_len)
{
  const char *ptr;

  ptr = str;
  do {
    if (0 == strncmp(ptr, pattern, pattern_len)
	&& ((',' == ptr[pattern_len]) || ('\0' == ptr[pattern_len]))) {
      return 1;
    }

    if (NULL != (ptr = strchr(ptr, ',')))
      ptr++;

  }
  while (NULL != ptr);

  return 0;
}

static char *
md5_str(const char *buf)
{
  const char *hex = "0123456789abcdef";
  struct md5_ctx ctx;
  unsigned char hash[16];
  char *r, *result;
  size_t length;
  int i;

  length = strlen(buf);
  result = xmalloc(33 * sizeof(char));
  md5_init_ctx(&ctx);
  md5_process_bytes(buf, length, &ctx);
  md5_finish_ctx(&ctx, hash);

  for (i = 0, r = result; i < 16; i++) {
    *r++ = hex[hash[i] >> 4];
    *r++ = hex[hash[i] & 0xF];
  }
  *r = '\0';

  return result;
}

static char *
dyn_strcat(const char *arg1, ...)
{
  const char *argptr;
  char *resptr, *result;
  int nargs = 0;
  size_t  len = 0;
  va_list valist;

  va_start(valist, arg1);

  for(argptr = arg1; argptr != NULL; argptr = va_arg(valist, char *))
    len += strlen(argptr);

  va_end(valist);

  result = xmalloc(len + 1);
  resptr = result;

  va_start(valist, arg1);

  nargs = 0;
  for(argptr = arg1; argptr != NULL; argptr = va_arg(valist, char *)) {
    len = strlen(argptr);
    memcpy(resptr, argptr, len);
    resptr += len;
  }

  va_end(valist);

  *resptr = '\0';

  return result;
}

static char *
get_h_a1(const DIGEST_CHLG *challenge, DIGEST_CRED *credentials, const char *nonce_value)
{
  char *h_usrepa, *result, *tmp;

  if (0 == strcasecmp("MD5", challenge->algorithm)) {
    tmp = dyn_strcat(credentials->username, ":", challenge->realm, ":", credentials->password, NULL);
    h_usrepa = md5_str(tmp);
    xfree(tmp);
    result = h_usrepa;
  }
  else if (0 == strcasecmp("MD5-sess", challenge->algorithm)) {
    if ((NULL == credentials->h_a1)) {
      tmp = dyn_strcat(credentials->username, ":", challenge->realm, ":", credentials->password, NULL);
      h_usrepa = md5_str(tmp);
      xfree(tmp);
      tmp = dyn_strcat(h_usrepa, ":", nonce_value, ":", credentials->cnonce_value, NULL);
      result = md5_str(tmp);
      xfree(tmp);
      credentials->h_a1 = result;
    }
    else {
      return credentials->h_a1;
    }
  }
  else {
    fprintf(stderr, "invalid call to %s algorithm is [%s]\n", __FUNCTION__, challenge->algorithm);
    return NULL;
  }

  return result;
}

char *
digest_generate_authorization(const DIGEST_CHLG *challenge,DIGEST_CRED *credentials,const char *method,const char *uri)
{
  char *nonce_count = NULL;
  char *cnonce = NULL;
  char *qop = NULL;
  char *response = NULL;
  char *request_digest = NULL;
  char *h_a1 = NULL;
  char *h_a2 = NULL;
  char *opaque = NULL;
  char *result, *tmp;

  if (NULL != challenge->qop) {
    nonce_count = dyn_strcat(", nc=", credentials->nc, NULL);
    cnonce = dyn_strcat(", cnonce=\"", credentials->cnonce_value, "\"", NULL);

    if (NULL == (h_a1 = get_h_a1(challenge, credentials, challenge->nonce))) {
      fprintf(stderr, "error calling get_h_a1\n");
      return NULL;
    }

    if (str_parse_list_has(challenge->qop, "auth", 4)) {
      qop = xstrdup(", qop=auth");
      tmp = dyn_strcat(method, ":", uri, NULL);
      h_a2 = md5_str(tmp);
      xfree(tmp);

      tmp = dyn_strcat(h_a1,":",challenge->nonce,":",credentials->nc,":",credentials->cnonce_value,":auth:",h_a2,NULL);
      request_digest = md5_str(tmp);
      xfree(tmp);
      response = dyn_strcat(", response=\"", request_digest, "\"", NULL);
    } else {
      fprintf(stderr, "error quality of protection not supported: %s\n", challenge->qop);
      return NULL;
    }
  } else {
    if (NULL == (h_a1 = get_h_a1(challenge, credentials, ""))) {
      fprintf(stderr, "error calling get_h_a1\n");
      return NULL;
    }
    tmp = dyn_strcat(method, ":", uri, NULL);
    h_a2 = md5_str(tmp);
    xfree(tmp);
    tmp = dyn_strcat(h_a1, ":", challenge->nonce, ":", h_a2, NULL);
    request_digest = md5_str(tmp);
    xfree(tmp);
    response = dyn_strcat(" response=\"", request_digest, "\"", NULL);
  }
  if (NULL != challenge->opaque)
    opaque = dyn_strcat(", opaque=\"", challenge->opaque, "\"", NULL);

  result = dyn_strcat("Digest username=\"", credentials->username, "\", realm=\"", challenge->realm, "\", nonce=\"", challenge->nonce, "\", uri=\"", uri, "\", algorithm=", challenge->algorithm, response, opaque ? opaque : "", qop ? qop : "", nonce_count ? nonce_count : "", cnonce ? cnonce : "", NULL);

  (credentials->nc_value)++;
  snprintf(credentials->nc, sizeof(credentials->nc), "%.8x", credentials->nc_value);

  if (0 == strcasecmp("MD5", challenge->algorithm))
    xfree(h_a1);
  xfree(nonce_count);
  xfree(cnonce);
  xfree(qop);
  xfree(response);
  xfree(request_digest);
  xfree(h_a2);
  xfree(opaque);

  return result;
}
