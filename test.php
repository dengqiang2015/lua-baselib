<?php
$str = '我是中国人';
$method = 'AES-128-CBC';
$secret_key = '123456';
$padding = OPENSSL_RAW_DATA;
$iv = '1234567890abcdef';

$enc = openssl_encrypt($str, $method, $secret_key, $padding, $iv);
echo $enc."\n";

$dec = openssl_decrypt($enc, $method, $secret_key, $padding, $iv);
echo $dec."\n";