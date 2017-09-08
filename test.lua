require 'baselib'
print(baselib.sha1('hello world'))
print(baselib.md5('hello world', 32))
print(baselib.md5('hello world', 16))

local t = {'aa', bb='vv', 'cc', dd='dd', ee={'zz','c', xx='xx'}}
print(baselib.tablen(t))

local str = '   string'
str = baselib.ltrim(str)
print(#str)
print(str)

str = 'string   '
str = baselib.rtrim(str)
print(str)
print(#str)

str = '    string    '
str = baselib.trim(str)
print(str)
print(#str)

str = 'string'
local t = baselib.str2table(str)
print(type(t))
for k,v in pairs(t) do
	print(k)
	print(v)
end 

t = {"str","i", "ng"}
str = baselib.table2str(t)
print(str)
print(#str)
print(baselib.base64_encode('string'))
print(baselib.base64_decode('c3RyaW5n'))
print(baselib.get_local_ip())
print(baselib.gethostbyname('www.baidu.com'))

print(baselib.urlencode('http://www.baidu.com'))
print(baselib.urldecode('http%3A%2F%2Fwww.baidu.com'))
print(baselib.strtoupper('string'))
print(baselib.strtolower('STRING'))
print(baselib.lcfirst('STRING'))
print(baselib.ucfirst('string'))
t = {a='aa',b='bb',c='cc',d='dd', 'ee', 'ff'}
for k,v in pairs(baselib.table_keys(t)) do
	print(k)
	print(v)
end

print(baselib.crc32('string'))

local key = 'a'
print(baselib.table_key_exists(key, t))
local key = 'aa'
print(baselib.table_key_exists(key, t))
local key = 2
print(baselib.table_key_exists(key, t))
local key = 3
print(baselib.table_key_exists(key, t))

t = {1,2,3.14,4,'a','b','c','d'}
for k,v in pairs(baselib.table_shuffle(t)) do
        print(v)
end

local str = 'avfdtrhs45gbvcssdsf67cbvcvb88vxcvcx11czcxz6xcvx788vvcx9jhhgu7rdd';
for k,v in pairs(baselib.split(str, '8')) do
	print(v)
end

print(baselib.join(t, '|'))
print(baselib.join(t, ''))

str = 'a=12345&b=string&c=abcde=#?[]@'
t = baselib.parse_str(str)
for k,v in pairs(t) do
        print(k)
        print(v)
end

findstr = 'str'
print(baselib.strpos(str, findstr))

findstr = 'Str'
print(baselib.stripos(str, findstr))
str, count = baselib.str_replace(str, '12345', '123')
print(str)
print(count)


t = baselib.parse_str(str)
print('#######')

for k,v in pairs(baselib.range(3)) do
       --print(k)
       print(v)
end
print('#######')
for k,v in pairs(baselib.range(-3)) do
       --print(k)
       print(v)
end
print('#######')

for k,v in pairs(baselib.range(5,10,2)) do
       --print(k)
       print(v)
end
print('#######')
for k,v in pairs(baselib.range(10,5)) do
       --print(k)
       print(v)
end
print('#######')
for k,v in pairs(baselib.range(-5,-10)) do
       --print(k)
       print(v)
end
print('#######')

for k,v in pairs(baselib.range(-10,-5)) do
       --print(k)
       print(v)
end
print('#######')

for k,v in pairs(baselib.range('f')) do
       --print(k)
       print(v)
end
print('#######')
for k,v in pairs(baselib.range('h', 'm')) do
       --print(k)
       print(v)
end
print('#######')

for k,v in pairs(baselib.range('m', 'h')) do
       --print(k)
       print(v)
end
print('#######')

for k,v in pairs(baselib.range('G')) do
       --print(k)
       print(v)
end
print('#######')
for k,v in pairs(baselib.range('W', 'Z')) do
       --print(k)
       print(v)
end
print('#######')

for k,v in pairs(baselib.range('Z', 'W')) do
       --print(k)
       print(v)
end
print('#######')

str = '我是中国人'
str = baselib.convert('UTF-8', 'GBK', str)
print(str)

str = baselib.convert('GBK', 'UTF-8', str)
print(str)

str = baselib.utf8_decode('GBK', str)
print(str)
str = baselib.utf8_encode('GBK', str)
print(str)

enc = baselib.aes_encrypt(str, '123456')
print(enc)

dec = baselib.aes_decrypt(enc, '123456')
print(dec)

print(baselib.getext('local.log'))

method = 'AES-128-CBC'--just like php openssl extension
secret_key = '123456'
pading = 'OPENSSL_RAW_DATA'--just like php openssl extension
iv = '1234567890abcdef'--16 bytes

enc = baselib.openssl_encrypt(str, method, secret_key, pading, iv);
print(enc)

dec = baselib.openssl_decrypt(enc, method, secret_key, pading, iv);
print(dec)
