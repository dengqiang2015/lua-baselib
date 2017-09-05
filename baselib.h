#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <string.h>

typedef struct tablekey
{       
    lua_Integer * numKey;
    char * strKey;
    lua_Integer strKeyLen;
}TBK;
