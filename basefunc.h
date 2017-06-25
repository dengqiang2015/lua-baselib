#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <ctype.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "sha1.h"

static unsigned char hexchars[] = "0123456789ABCDEF";  
static int htoi(char * s);
char * urlencode(char const *s, int len);
char * urldecode(char * str, int len);
unsigned char *base64_encode(const unsigned char *str);
unsigned char *base64_decode(const unsigned char *str, int strict);
int get_local_ip(char * ifname, char * ip);
char * rtrim(char * s, size_t len);
char * ltrim(char * s);
char * trim(char * s, size_t len);
