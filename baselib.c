#include "baselib.h"
#include <string.h>
#include "basefunc.c"


static int baselib_stripos(lua_State *L)
{
	const char * src = luaL_checkstring(L, -2);
	const char * findstr = luaL_checkstring(L, -1);
	int srclen = strlen(src);
	int findstrlen = strlen(findstr);
	if(srclen == 0 || findstrlen == 0)
	{
		lua_pushnil(L);
		return 1;
	}
	const char * startpos = src;
	char * endpos = (char *)strcasestr(src, findstr);
	int pos = 0;
	if(endpos == NULL)
	{
		lua_pushnil(L);
	}
	else
	{
		pos = (int)(endpos-startpos);
		lua_pushnumber(L, pos);
	}
	return 1;	
}

static int baselib_strpos(lua_State *L)
{
	const char * src = luaL_checkstring(L, -2);
	const char * findstr = luaL_checkstring(L, -1);
	int srclen = strlen(src);
	int findstrlen = strlen(findstr);
	if(srclen == 0 || findstrlen == 0)
	{
		lua_pushnil(L);
		return 1;
	}
	const char * startpos = src;
	char * endpos = strstr(src, findstr);
	int pos = 0;
	if(endpos == NULL)
	{
		lua_pushnil(L);
	}
	else
	{
		pos = (int)(endpos-startpos);
		lua_pushnumber(L, pos);
	}
	return 1;	
}

static int baselib_parse_str(lua_State *L)
{

	const char * src = luaL_checkstring(L, 1);
	int len = strlen(src);
	char * srccp = (char *)calloc(len, sizeof(char));
	memcpy(srccp, src, len);
	char * item;
	char * k;
	char * v;
	char * kp;
	char * vp;
	int split = 0;
	int itemlen = 0;
	lua_createtable(L,0,0);
	if(len > 0)
	{
	   item = strtok(srccp, "&");
	    while((item != NULL))
		{
			split = 0;
			itemlen = strlen(item);
			k = (char *)malloc(itemlen*sizeof(char));
			v = (char *)malloc(itemlen*sizeof(char));
			memset(k, '\0', itemlen);
			memset(v, '\0', itemlen);
			kp = k;
			vp = v;
			while(*item != '\0')
			{
				if( *item == '=' && split == 0)
				{
					split = 1;
					item++;
					continue;
				}

				(split == 0) ? (*kp++ = *item++) : (*vp++ = *item++);
					
			}
			lua_pushstring(L, k);
			lua_pushstring(L, v);
			lua_settable(L, -3); 		
			item = strtok(NULL, "&");
		}
	}
	free(srccp);
	free(item);
	return 1;	
}

static int baselib_join(lua_State *L)
{
	const char * cts = luaL_checkstring(L, -1);
	const char * ctsi;
	int ctslen = strlen(cts);
	lua_pop(L, 1);
	int key;
	const char * val;
	char * str = (char*)calloc(1,sizeof(char));
	size_t vlen;
	size_t len=0;
	char * i;
	lua_pushnil(L);
	while(0 != lua_next(L, -2))
	{
		ctsi = cts;
		val = luaL_checkstring(L, -1);
		key = luaL_checknumber(L, -2);
		vlen = strlen(val);
		if(vlen > 0)
		{
			str = (char *)realloc(str, (len+vlen+ctslen) * sizeof(char));
			for(i = str+len; i<str+len+vlen+ctslen; i++)
			{
				*i = (*val != '\0') ? *val++ : *ctsi++;
			}
			len = len+vlen+ctslen;
		}
		lua_pop(L, 1);
	}
	*(i-ctslen) = '\0';
	lua_pushstring(L, str);
	return 1;
}

static int baselib_split(lua_State *L)
{
	const char * src = luaL_checkstring(L, -2);
	const char * delim = luaL_checkstring(L, -1);
	int i = 1;
	int srclen = strlen(src);
	int delimlen = strlen(delim);
	char * srccp = (char *)calloc(srclen, sizeof(char));
	char * p;

	memcpy(srccp, src, srclen);
	lua_pop(L, 1);
	lua_pop(L, 1);
	lua_createtable(L,0,0);
	if(srclen > 0 && delimlen > 0)
	{
		p = strtok(srccp, delim);
	    	while((p != NULL))
		{
			lua_pushnumber(L, i++);
			lua_pushstring(L, p);
			lua_settable(L, -3);
			p = strtok(NULL, delim);
		}
	}

	free(srccp);
	free(p);
	return 1;	
}

static int baselib_table_shuffle(lua_State *L)
{	
	typedef struct tableval
	{
			double * numVal;
			char * strVal;
			int strValLen;
	}TBV;

	size_t extend = 256;
	int idx = 0;
	TBV *vals = NULL;
	TBV *tmpval = NULL;
	if(lua_type(L, 1) == LUA_TTABLE)
	{
		vals = (TBV *)calloc(extend, sizeof(TBV));
		tmpval = (TBV *)calloc(1, sizeof(TBV));
		int len = 0;
		int i = 0;
		tmpval[0].numVal = NULL;
		tmpval[0].strVal = NULL;
		tmpval[0].strValLen = 0;
		srand((unsigned)time(NULL));
		int k = 0;
		lua_pushnil(L);
		while(lua_next(L, -2))
		{
			if(lua_type(L, -1) == LUA_TSTRING)
			{
				if(idx >0 && idx%extend == 0)
				{
					vals = (TBV *)realloc(vals, (idx+extend)*sizeof(TBV));
				}
				vals[idx].numVal = NULL;
				vals[idx].strVal = NULL;
				vals[idx].strValLen = 0;
				const char * src = luaL_checkstring(L, -1);
				len = strlen(src);
				char * srccp = (char *)calloc(len, sizeof(char));
				memcpy(srccp, src, len);
				vals[idx].strVal = srccp;
				vals[idx++].strValLen = len;
			}
			else if(lua_type(L, -1) == LUA_TNUMBER)
			{
				vals[idx].numVal = NULL;
				vals[idx].strVal = NULL;
				vals[idx].strValLen = 0;	
				if(idx >0 && idx%extend == 0)
				{		   
					vals = (TBV *)realloc(vals, (idx+extend)*sizeof(TBV));
				}
				const int num = luaL_checknumber(L, -1);
				double * numcp = (double *)calloc(1, sizeof(double));
				*numcp = num;
				vals[idx++].numVal = numcp;
			}
			else
			{

			}
			lua_pop(L, 1);
		}
		
		
		for(i=0;i<idx;i++)
		{
			k = rand()%idx+0;
			tmpval[0].numVal = vals[i].numVal;
			tmpval[0].strVal = vals[i].strVal;
			tmpval[0].strValLen = vals[i].strValLen;
			vals[i].numVal = vals[k].numVal;
			vals[i].strVal = vals[k].strVal;
			vals[i].strValLen = vals[k].strValLen;
			vals[k].numVal = tmpval[0].numVal;
			vals[k].strVal = tmpval[0].strVal;
			vals[k].strValLen = tmpval[0].strValLen;
		}

		lua_createtable(L, 0, 0);

		for(i=0;i<idx;i++)
		{
			lua_pushnumber(L, i+1);
			if(vals[i].strValLen > 0)
			{
				lua_pushstring(L, vals[i].strVal);
			}
			else if(vals[i].numVal != NULL)
			{
				lua_pushnumber(L, *vals[i].numVal);
			}
			else
			{
				lua_pushnil(L);
			}
			lua_settable(L, -3);
		}

	}
	else
	{
		lua_createtable(L, 0, 0);
	}
	free(vals);	
	free(tmpval);
	return 1;
}

static int baselib_table_key_exists(lua_State *L)
{
	
	int numKey;
	int type = 0;
	const char * strKey;
	int strKeyLen = 0;

	if(lua_type(L, -2) == LUA_TNUMBER)
	{
		numKey = luaL_checknumber(L, -2);						
	}
	else if(lua_type(L, -2) == LUA_TSTRING)
	{
		type = 1;
		strKey = luaL_checkstring(L, -2);
		strKeyLen = strlen(strKey);
	}
	else
	{
		lua_pushboolean(L, 0);
		return 1;
	}


	if(!lua_istable(L, -1))
	{
		lua_pushboolean(L, 0);
		return 1;
	}

	lua_pushnil(L);
		while(lua_next(L, -2))
		{
		
		if(lua_type(L, -2) == LUA_TSTRING)
		{
			if(type == 1)
			{
				const char * srcStr = luaL_checkstring(L, -2);	
				if(0 == strcmp(strKey, srcStr))
				{
					lua_pushboolean(L, 1);
					return 1;
				}
			}	
		}
		else if(lua_type(L, -2) == LUA_TNUMBER)
		{
			if(type == 0)
			{
				int srcNum	= luaL_checknumber(L, -2);
				if(srcNum == numKey)
				{
					lua_pushboolean(L, 1);
					return 1;
				}
			}
		}
		else
		{
			lua_pushboolean(L, 0);
			return 1;
		}
		lua_pop(L, 1);
	}


	lua_pushboolean(L, 0);
	return 1;
	
}


static int baselib_crc32(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	uint32_t len = strlen(src);
	uint32_t crc = crc32(src, len);
	lua_pushnumber(L, crc);
	return 1;		
}


static int baselib_table_keys(lua_State *L)
{	
	size_t extend = 256;
	int idx = 0;
	TBK *keys = NULL;
	if(lua_type(L, 1) == LUA_TTABLE)
	{
		keys = (TBK *)calloc(extend, sizeof(TBK));
		int len = 0;
		int i = 0;
		lua_pushnil(L);
		while(lua_next(L, -2))
		{
			if(lua_type(L, -2) == LUA_TSTRING)
			{
				if(idx >0 && idx%extend == 0)
				{
					keys = (TBK *)realloc(keys, (idx+extend)*sizeof(TBK));
				}
				keys[idx].numKey = NULL;
				keys[idx].strKey = NULL;
				keys[idx].strKeyLen = 0;
				const char * src = luaL_checkstring(L, -2);
				len = strlen(src);
				char * srccp = (char *)calloc(len, sizeof(char));
				memcpy(srccp, src, len);
				keys[idx].strKey = srccp;
				keys[idx++].strKeyLen = len;
			}
			else if(lua_type(L, -2) == LUA_TNUMBER)
			{
				keys[idx].numKey = NULL;
				keys[idx].strKey = NULL;
				keys[idx].strKeyLen = 0;	
				if(idx >0 && idx%extend == 0)
				{		   
					keys = (TBK *)realloc(keys, (idx+extend)*sizeof(TBK));
				}
				const int num = luaL_checknumber(L, -2);
				int * numcp = (int *)calloc(1, sizeof(int));
				*numcp = num;
				keys[idx++].numKey = numcp;
			}
			else
			{

			}
			lua_pop(L, 1);
		}

			lua_createtable(L, 0, 0);

			for(i=0;i<idx;i++)
			{
				lua_pushnumber(L, i+1);
				if(keys[i].strKeyLen > 0)
				{
					lua_pushstring(L, keys[i].strKey);
				}
				else if(keys[i].numKey != NULL)
				{
					lua_pushnumber(L, *keys[i].numKey);
				}
				else
				{
					lua_pushnil(L);
				}
				lua_settable(L, -3);
			}

	}
	else
	{
		lua_createtable(L, 0, 0);
	}
		
		return 1;
}

static int baselib_ucfirst(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	size_t len = strlen(src);
	char * newstr = (char *)calloc(len, sizeof(char));
	memcpy(newstr, src, len);
	char * s = newstr;
	*s = toupper(*s);
	lua_pushstring(L, newstr);
	return 1;	
}


static int baselib_lcfirst(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	size_t len = strlen(src);
	char * newstr = (char *)calloc(len, sizeof(char));
	memcpy(newstr, src, len);
	char * s = newstr;
	*s = tolower(*s);
	lua_pushstring(L, newstr);
	return 1;
}


static int baselib_strtolower(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	int len = strlen(src);
	char * newstr = (char *)calloc(len, sizeof(char));
	memcpy(newstr, src, len);
	char * s = newstr;
	while( *s != '\0')
	{
		*s = tolower(*s);
		s++;
	}
	lua_pushstring(L, newstr);
	return 1;
}

static int baselib_strtoupper(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	int len = strlen(src);
	char * newstr = (char *)calloc(len, sizeof(char));
	memcpy(newstr, src, len);
	char * s = newstr;
	while( *s != '\0')
	{
		*s = toupper(*s);
		s++;
	}
	lua_pushstring(L, newstr);
	return 1;
}

static int baselib_urlencode(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	int len = strlen(src);
	char * newstr = urlencode(src, len);
	lua_pushstring(L, newstr);
	return 1;
}

static int baselib_urldecode(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	int len = strlen(src);
	char * srccp = (char *)calloc(len, sizeof(char));
	memcpy(srccp, src, len);
	char * newstr = urldecode(srccp, len);
	lua_pushstring(L, newstr);
	return 1;
}

static int baselib_base64_encode(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	unsigned char * newstr = base64_encode(src);
	lua_pushstring(L, newstr);
	return 1;
	
}


static int baselib_base64_decode(lua_State *L)
{
	const unsigned char * src = luaL_checkstring(L, 1);
	unsigned char * newstr = base64_decode(src, 1);
	lua_pushstring(L, newstr);
	return 1;
}


static int baselib_get_local_ip(lua_State *L)
{
	char ip[32]={'\0'};
	int lt = lua_type(L, 1);
	if(lt != LUA_TSTRING){
		get_local_ip("eth0", ip);
	}else{
		const char * src = luaL_checkstring(L, 1);
		size_t len = strlen(src);
		char * ifname = (char*)calloc (1, len);
		memset(ifname, '\0', len);
		memcpy (ifname, src, len);
		if(len>0)
		{
			get_local_ip(ifname, ip);
		}
		else
		{
			get_local_ip("eth0", ip);
		}
		free(ifname);
   }

   lua_pushstring(L, ip);
   return 1;
}

static int baselib_gethostbyname(lua_State *L)
{
	char ip[32]={'\0'};
	int lt = lua_type(L, 1);
	if(lt != LUA_TSTRING){
		lua_pushnil(L);
	}else{
		const char * hostname = luaL_checkstring(L, 1);
		hostname2ip(hostname , ip);
		lua_pushstring(L, ip);
   }

   return 1;
}

static int baselib_table2str(lua_State *L)
{
	int key;
	const char * val;
	char * str = (char*)calloc(1, sizeof(char));
	size_t vlen;
	size_t len=0;
	char * i;
	lua_pushnil(L);
	while(0 != lua_next(L, -2))
	{
		val = luaL_checkstring(L, -1);
		key = luaL_checknumber(L, -2);
		vlen = strlen(val);
		if(vlen > 0)
		{
			str = (char *)realloc(str, (len+vlen) * sizeof(char));
			for(i = str+len; i<str+len+vlen; i++)
			{
				*i = *val++;
			}
			len = len + vlen;
		}
		lua_pop(L, 1);
	}
	lua_pushstring(L, str);
	return 1;
	
}

static int baselib_str2table(lua_State *L)
{
	const char * src = luaL_checkstring(L, 1);
	int i=1;
	int len = strlen(src);
	char * c = (char *)calloc(1, sizeof(char));
	lua_pop(L, 1);
	lua_createtable(L,0,0);
	if(len > 0)
	{
		while(*src != '\0'){
			sprintf(c, "%c", *src++);
			lua_pushnumber(L, i++);
			lua_pushstring(L, c);
			lua_settable(L, -3);
		}
	}
	return 1;	
}


static int baselib_rtrim(lua_State *L)
{		
		const char * src = luaL_checkstring(L, 1);
		size_t len= strlen(src);
		if(len>0)
		{		
			char * srccp = (char *)calloc(len, sizeof(char));
			memcpy(srccp, src, len);
			char * newstr = rtrim(srccp, len);
			lua_pushstring(L, newstr);
		}
		else
		{
			lua_pushstring(L, "");
		}
		return 1;
}

static int baselib_ltrim(lua_State *L)
{
	const char * src = luaL_checkstring(L, 1);
	size_t len= strlen(src);
	if(len>0)
	{
		char * srccp = (char *)calloc(len, sizeof(char));
		memcpy(srccp, src, len);
		char * newstr = ltrim(srccp);
		lua_pushstring(L, newstr);
	}
	else
	{
		lua_pushstring(L, "");
	}
	return 1;	
}


static int baselib_tablen(lua_State *L) 
{
	int len = 0;
	lua_pushnil(L);	 
	while(lua_next(L, -2))	
	{  
		len++;
		lua_pop(L, 1);	
	}  
	lua_pushnumber(L, len);
	return 1;
} 

static int baselib_trim(lua_State *L) 
{
	const char * src = luaL_checkstring(L, 1);
		size_t len= strlen(src);
		if(len>0)
		{		
			char * srccp = (char *)calloc(len, sizeof(char));
			memcpy(srccp, src, len);
			char * newstr = (char *)trim(srccp, len);
			lua_pushstring(L, newstr);
		}
	else
	{
		lua_pushstring(L, "");
	}
	return 1;
}



static int baselib_sha1(lua_State *L) 

{
	char buf[128];
	const char *src = luaL_checkstring(L, 1);
	sha1_hash(src, "SHA1", buf);
	lua_pushstring(L, buf);
	return 1;

}


static int baselib_md5(lua_State *L)
{
	unsigned char decrypt[16]={'\0'};
	unsigned char buf[33]={'\0'};
	const char * src = luaL_checkstring(L, 1);
	size_t len = strlen(src);
	unsigned char * str = (char*)calloc(len, sizeof(char));
	memcpy(str, src, len);
	int md5_len = luaL_checkinteger(L, 2);
	MD5_CTX md5;  
	MD5Init(&md5);			 
	MD5Update(&md5, str, len);	
	MD5Final(&md5, decrypt);
	free(str);
	int i;
	if(md5_len == 16)
	{
		for(i=4; i<12; i++)
		{
			sprintf(buf+(i-4)*2, "%02x", decrypt[i]);
		}
	}
	else if(md5_len == 32)
	{
		for(i=0; i<16; i++)
		{
			sprintf(buf+i*2, "%02x", decrypt[i]);
		}
	}
	else
	{
	}
	lua_pushstring(L, buf);
	return 1;	   
}

static const struct luaL_Reg baselib[] = {

	
	{"sha1", baselib_sha1},
	{"md5", baselib_md5},
	{"tablen", baselib_tablen},
	{"ltrim", baselib_ltrim},
	{"rtrim", baselib_rtrim},
	{"trim", baselib_trim},
	{"str2table", baselib_str2table},
	{"table2str", baselib_table2str},
	{"gethostbyname", baselib_gethostbyname},
	{"get_local_ip", baselib_get_local_ip},
	{"gethostbyname", baselib_gethostbyname},
	{"base64_encode", baselib_base64_encode},
	{"base64_decode", baselib_base64_decode},
	{"urlencode", baselib_urlencode},
	{"urldecode", baselib_urldecode},
	{"strtoupper", baselib_strtoupper},
	{"strtolower", baselib_strtolower},
	{"ucfirst", baselib_ucfirst},
	{"lcfirst", baselib_lcfirst},
	{"table_keys", baselib_table_keys},
	{"crc32", baselib_crc32},
	{"table_key_exists", baselib_table_key_exists},
	{"table_shuffle", baselib_table_shuffle},
	{"split", baselib_split},
	{"join", baselib_join},
	{"parse_str", baselib_parse_str},
	{"strpos", baselib_strpos},
	{"stripos", baselib_stripos},
	{NULL, NULL}

};

int luaopen_baselib(lua_State *L)

{

	luaL_register(L, "baselib", baselib);
	return 1;
}
