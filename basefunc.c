#include "basefunc.h"
#include "md5.c"
 
 static lua_Integer htoi(char * s)  
{  
    lua_Integer value;  
    lua_Integer c;  
  
    c = ((unsigned char *)s)[0];  
    if (isupper(c))  
        c = tolower(c);  
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;  
  
    c = ((unsigned char *)s)[1];  
    if (isupper(c))  
        c = tolower(c);  
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;  
  
    return (value);  
}

char * urlencode(char const *s, lua_Integer len)  
{  
    register unsigned char c;  
    unsigned char *to, *start;  
    unsigned char const *from, *end;  
      
    from = (unsigned char *)s;  
    end  = (unsigned char *)s + len;  
    start = to = (unsigned char *) calloc(1, 3*len+1);  
  
    while (from < end)   
    {  
        c = *from++;  
  
        if (c == ' ')   
        {  
            *to++ = '+';  
        }   
        else if ((c < '0' && c != '-' && c != '.') ||  
                 (c < 'A' && c > '9') ||  
                 (c > 'Z' && c < 'a' && c != '_') ||  
                 (c > 'z'))   
        {  
            to[0] = '%';  
            to[1] = hexchars[c >> 4];  
            to[2] = hexchars[c & 15];  
            to += 3;  
        }  
        else   
        {  
            *to++ = c;  
        }  
    }  
    *to = 0;  
    return (char *) start;  
}



char * urldecode(char * str, lua_Integer len)  
{  
    char * dest = str;  
    char * data = str;  
  
    while (len--)   
    {  
        if (*data == '+')   
        {  
            *dest = ' ';  
        }  
        else if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1)) && isxdigit((int) *(data + 2)))   
        {  
            *dest = (char) htoi(data + 1);  
            data += 2;  
            len -= 2;  
        }   
        else   
        {  
            *dest = *data;  
        }  
        data++;  
        dest++;  
    }  
    *dest = '\0';
    return str;
}  



unsigned char *base64_encode(const unsigned char *str)
{
    static const char base64_table[] =
    { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
      'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
    };
    static const char base64_pad = '=';
    const unsigned char *current = str;
    lua_Integer length = strlen(str);
    unsigned char *p;
    unsigned char *result;

    if ((length + 2) < 0 || ((length + 2) / 3) >= (1 << (sizeof(int) * 8 - 2))) {
        return NULL;
   }

    result = (unsigned char *)malloc(((length + 2) / 3) * 4 * sizeof(char) + 1);
    p = result;

    while (length > 2) { 
        *p++ = base64_table[current[0] >> 2];
        *p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
        *p++ = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
        *p++ = base64_table[current[2] & 0x3f];

        current += 3;
        length -= 3; 
    }

    if (length != 0) {
        *p++ = base64_table[current[0] >> 2];
        if (length > 1) {
            *p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
            *p++ = base64_table[(current[1] & 0x0f) << 2];
            *p++ = base64_pad;
        } else {
            *p++ = base64_table[(current[0] & 0x03) << 4];
            *p++ = base64_pad;
            *p++ = base64_pad;
        }
    }
    *p = '\0';
    return result;
}



unsigned char *base64_decode(const unsigned char *str, lua_Integer strict)
{
    static const char base64_pad = '=';
    static const short base64_reverse_table[256] = {
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
        -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
        -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
    };
    const unsigned char *current = str;
    lua_Integer length = strlen(str);
    lua_Integer ch, i = 0, j = 0, k;
    
    unsigned char *result;
    
    result = (unsigned char *)malloc(length + 1);

    
    while ((ch = *current++) != '\0' && length-- > 0) {
        if (ch == base64_pad) {
            if (*current != '=' && (i % 4) == 1) {
                free(result);
                return NULL;
            }
            continue;
        }

        ch = base64_reverse_table[ch];
        if ((!strict && ch < 0) || ch == -1) { 
            continue;
        } else if (ch == -2) {
            free(result);
            return NULL;
        }

        switch(i % 4) {
        case 0:
            result[j] = ch << 2;
            break;
        case 1:
            result[j++] |= ch >> 4;
            result[j] = (ch & 0x0f) << 4;
            break;
        case 2:
            result[j++] |= ch >>2;
            result[j] = (ch & 0x03) << 6;
            break;
        case 3:
            result[j++] |= ch;
            break;
        }
        i++;
    }

    k = j;
    
    if (ch == base64_pad) {
        switch(i % 4) {
        case 1:
            free(result);
            return NULL;
        case 2:
            k++;
        case 3:
            result[k++] = 0;
        }
    }

    result[j] = '\0';
    return result;
}


lua_Integer get_local_ip(char * ifname, char * ip)
{
    char *temp = NULL;
    lua_Integer inet_sock;
    struct ifreq ifr;

    inet_sock = socket(AF_INET, SOCK_DGRAM, 0);

    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    memcpy(ifr.ifr_name, ifname, strlen(ifname));

    if(0 != ioctl(inet_sock, SIOCGIFADDR, &ifr))
    {
        perror("ioctl error");
        return -1;
    }

    temp = inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr);
    memcpy(ip, temp, strlen(temp));

    close(inet_sock);

    return 0;
}



char * rtrim(char * s, lua_Integer  len)
{

	char * i = s+len-1;
    for(i; isspace(*i) && i>s; i--){
    	(*i) = '\0';
    }
	
	return s;
}



char * ltrim(char * s)
{
	
	while(isspace(*s) && *s != '\0')
	{
		s++;
	}

    return s;
}



char * trim(char * s, lua_Integer  len)
{
	char * i = s+len-1;
	while(isspace(*s) && *s != '\0'){
		s++;
	}
	for(i; isspace(*i) && i>s; i--){
		(*i) = '\0';
	}
	return s;
}


lua_Integer  crc32( const unsigned char *buf, lua_Integer  size)
{
	lua_Integer  i, crc;
	crc = 0xFFFFFFFF;
	for (i = 0; i < size; i++)
	{
     		crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
	}
     	return crc^0xFFFFFFFF;
}


lua_Integer hostname2ip(const char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    lua_Integer i;
         
    if ( (he = gethostbyname( hostname ) ) == NULL) 
    {

        return 1;
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
    {
  
        strcpy(ip, inet_ntoa(*addr_list[i]) );
        return 0;
    }
     
    return 1;
}


/* 
 * String matching - Sunday algorithm
 */
void memnstr_pre(lua_Integer  td[], const char *needle, lua_Integer  needle_len, lua_Integer reverse) {
	lua_Integer i;

	for (i = 0; i < 256; i++) {
		td[i] = needle_len + 1;
	}

	if (reverse) {
		for (i = needle_len - 1; i >= 0; i--) {
			td[(unsigned char)needle[i]] = i + 1;
		}
	} else {
		lua_Integer  i;

		for (i = 0; i < needle_len; i++) {
			td[(unsigned char)needle[i]] = (int)needle_len - i;
		}
	}
}


const char *memnstr(const char *haystack, const char *needle, lua_Integer  needle_len, const char *end)
{
	lua_Integer  td[256];
	register lua_Integer  i;
	register const char *p;

	if (needle_len == 0 || (end - haystack) == 0) {
		return NULL;
	}
	
	memnstr_pre(td, needle, needle_len, 0);

	p = haystack;
	end -= needle_len;

	while (p <= end) {
		for (i = 0; i < needle_len; i++) {
			if (needle[i] != p[i]) {
				break;
			}
		}
		if (i == needle_len) {
			return p;
		}
		if (p == end) {
			return NULL;
		}
		p += td[(unsigned char)(p[needle_len])];
	}

	return NULL;
}

const char *str_replace(const char *haystack, lua_Integer haystack_len,const char *needle, lua_Integer  needle_len, const char *str, lua_Integer  str_len, lua_Integer  *replace_count)
{
	char *new_str;
	if (needle_len < haystack_len) {
		const char *end;
		const char *p, *r;
		char *e, *s;

		if (needle_len == str_len) {
			new_str = NULL;
			end = haystack + haystack_len;
			for (p = haystack; (r = (char *)memnstr(p, needle, needle_len, end)); p = r + needle_len) {
				if (!new_str) {
					new_str = (char *)malloc(haystack_len*sizeof(char));
					memcpy(new_str, haystack, haystack_len);
				}
				memcpy(new_str + (r - haystack), str, str_len);
				(*replace_count)++;
			}
			if (!new_str) {
			
				return haystack;
			}
	
			return (const char *)new_str;
		} else {
			lua_Integer  count = 0;
			const char *o = haystack;
			const char *n = needle;
			const char *endp = o + haystack_len;

			while ((o = (char *)memnstr(o, n, needle_len, endp))) {
				o += needle_len;
				count++;
			}
			if (count == 0) {
				return haystack;
			}
		
			new_str = (char *)malloc((count * (str_len - needle_len) + haystack_len)*sizeof(char));

			e = s = new_str;
			end = haystack + haystack_len;
			for (p = haystack; (r = (char *)memnstr(p, needle, needle_len, end)); p = r + needle_len) {
				memcpy(e, p, r - p);
				e += r - p;
		
				memcpy(e, str, str_len);
				(*replace_count)++;
				e += str_len;
			}

			if (p < end) {
				memcpy(e, p, end - p);
				e += end - p;
			}

			*e = '\0';
	
			return (const char *)new_str;
		}
	} else if (needle_len > haystack_len || memcmp(haystack, needle, haystack_len)) {

		return haystack;
	}else {
		new_str = (char *)malloc(str_len*sizeof(char));
		memcpy(new_str, str, str_len);
		(*replace_count)++;

		return (const char *)new_str;
	}
}
