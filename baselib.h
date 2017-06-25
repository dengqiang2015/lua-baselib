#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

typedef struct tablekey
{       
        int * numKey;
        char * strKey;
        int strKeyLen;
}TBK;
