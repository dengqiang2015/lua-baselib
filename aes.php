<?php
class AES{  
    /** 
     * �㷨,���⻹��192��256���ֳ��� 
     */  
    const CIPHER = MCRYPT_RIJNDAEL_128;  
    /** 
     * ģʽ  
     */  
    const MODE = MCRYPT_MODE_ECB;  
  
    /** 
     * ���� 
     * @param string $key   ��Կ 
     * @param string $str   ����ܵ��ַ��� 
     * @return type  
     */  
    static public function encode( $key, $str ){  
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(self::CIPHER,self::MODE),MCRYPT_RAND);  
        return mcrypt_encrypt(self::CIPHER, $key, $str, self::MODE, $iv);  
    }  
      
    /** 
     * ���� 
     * @param type $key 
     * @param type $str 
     * @return type  
     */  
    static public function decode( $key, $str ){  
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(self::CIPHER,self::MODE),MCRYPT_RAND);  
        return mcrypt_decrypt(self::CIPHER, $key, $str, self::MODE, $iv);  
    }  
} 

$str = '�����й���';  
$key = '1234567890';  
$s = microtime(true);
for($i=0;$i<100000;$i++)
{
$enc=AES::encode($key, $str);  
$dec=AES::decode($key, $str1); 
}
$e = microtime(true);