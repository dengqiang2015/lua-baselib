local baselib = require "baselib"                                                                                              
str = '我是中国人'                                                                                                             
secretkey = '1234567890'                                                                                                       
--ngx.say(ngx.now())                                                                                                           
local s = os.clock()                                                                                                           
i=0                                                                                                                            
print(s)                                                                                                                       
while(i<100000)                                                                                                                 
do                                                                                                                             
    enc = baselib.aes_encrypt(str, secretkey)                                                                                  
    dec = baselib.aes_decrypt(enc, secretkey)                                                                                  
    i=i+1                                                                                                                      
end                                                                                                                            
local e = os.clock()                                                                                                           
print(e)
