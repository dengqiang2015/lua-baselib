# lua-baselib
<br>
**Introduction:** Lua base function library, including some CPU intensive functions.
<br>
<br>
**Dependency Library:** openssl
<br>
<br>
**Compile notes:**
<br>
You need to modify the Lua header file path and the Lua library path and the Lua module path in the Makefile file.
<br>
Such as:
<br>
LUACPATH ?= (lua module path)
<br>
INCDIR   ?= -I (Lua header file path)
<br>
LIBDIR   ?= -L (Lua library path) -lssl
<br>
<br>

**Base functions list:**
<br>
sha1
<br>
md5
<br>
tablen
<br>
ltrim
<br>
rtrim
<br>
trim
<br>
str2table
<br>
table2str
<br>
get_local_ip
<br>
base64_encode
<br>
base64_decode
<br>
urlencode
<br>
urldecode
<br>
strtoupper
<br>
strtolower
<br>
ucfirst
<br>
table_keys
<br>
crc32
<br>
table_key_exists
<br>
table_shuffle
<br>
split
<br>
join
<br>
parse_str
<br>
strpos
<br>
stripos
<br>
str_replace
<br>
range
<br>
convert
<br>
utf8_encode
<br>
utf8_decode
<br>
<br>

**How to use:**
<br>
require 'baselib'
<br>
print(baselib.sha1('hello world'))
<br>
<br>

**More examples:**
<br>
View the test.lua file