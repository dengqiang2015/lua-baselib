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
