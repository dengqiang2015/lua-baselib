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
