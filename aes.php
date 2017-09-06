<?php
class AES{  
    /** 
     * 算法,另外还有192和256两种长度 
     */  
    const CIPHER = MCRYPT_RIJNDAEL_128;  
    /** 
     * 模式  
     */  
    const MODE = MCRYPT_MODE_ECB;  
  
    /** 
     * 加密 
     * @param string $key   密钥 
     * @param string $str   需加密的字符串 
     * @return type  
     */  
    static public function encode( $key, $str ){  
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(self::CIPHER,self::MODE),MCRYPT_RAND);  
        return mcrypt_encrypt(self::CIPHER, $key, $str, self::MODE, $iv);  
    }  
      
    /** 
     * 解密 
     * @param type $key 
     * @param type $str 
     * @return type  
     */  
    static public function decode( $key, $str ){  
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(self::CIPHER,self::MODE),MCRYPT_RAND);  
        return mcrypt_decrypt(self::CIPHER, $key, $str, self::MODE, $iv);  
    }  
} 

$str = '我是中国人';  
$key = '1234567890';  
$s = microtime(true);
for($i=0;$i<100000;$i++)
{
$enc=AES::encode($key, $str);  
$dec=AES::decode($key, $str1); 
}
$e = microtime(true);