#ifndef AUTH_H
#define AUTH_H

/**
 * authorization service
 */
typedef enum { WWW,   PROXY  } SERVICE; 

struct LOGIN
{
  char *realm; 
  char *username;
  char *password;
  struct LOGIN *next;
};  


/**
 * authorization type
 */
typedef enum { BASIC, DIGEST } TYPE;

void add_authorization(SERVICE S, char *username, char *password, char *realm); 
int  display_authorization(SERVICE S); 
int  set_authorization(SERVICE S, char *realm); 

typedef struct DIGEST_CRED DIGEST_CRED;
typedef struct DIGEST_CHLG DIGEST_CHLG;

int  set_digest_authorization(SERVICE S, DIGEST_CHLG **challenge, DIGEST_CRED **credentials, unsigned int *randseed, char *realm, char *str);
void digest_challenge_destroy(DIGEST_CHLG *challenge);
void digest_credential_destroy(DIGEST_CRED *credentials);
char *digest_generate_authorization(const DIGEST_CHLG *challenge, DIGEST_CRED *credentials, const char *method, const char *uri);

#endif/*AUTH_H*/
