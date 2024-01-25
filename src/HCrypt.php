<?php

namespace Mhavid\Kzcrypt;

/**
 * Encrypt/Decrypt data with php x javascript
 * PHP 7.x or later support
 * @version 1.0.0
 */
class Kzcrypt {

    /**
     * Function to encrypt data
     */
    public static function encrypt($value, string $secret)
    {
        try {
            $salt = openssl_random_pseudo_bytes(8);
            $salted = '';
            $hashing = '';
            while (strlen($salted) < 48) {
                $hashing = md5($hashing . $secret . $salt, true);
                $salted .= $hashing;
            }
            $key = substr($salted, 0, 32);
            $iv  = substr($salted, 32, 16);
            $encrypted_data = openssl_encrypt(json_encode($value), 'aes-256-cbc', $key, true, $iv);
            return base64_encode('Salted__' . $salt . $encrypted_data);
        } catch (\Throwable $th) {
            throw $th;
        }
    }


    /**
     * Function to decrypt data
     */
    public static function decrypt(string $value, string $secret)
    {
        try {
            $salt = openssl_random_pseudo_bytes(8);
            $salted = '';
            $hashing = '';
            while (strlen($salted) < 48) {
                $hashing = md5($hashing . $secret . $salt, true);
                $salted .= $hashing;
            }
            $key = substr($salted, 0, 32);
            $iv  = substr($salted, 32, 16);
            $enct = base64_decode($value);
            $buffer = $key . $salt;
            $md5 = [];
            $md5[0] = md5($buffer, true);
            $result = $md5[0];
            $i = 1;
            while (strlen($result) < 32) {
                $md5[$i] = md5($md5[$i - 1] . $buffer, true);
                $result .= $md5[$i];
                $i++;
            }
            $key = substr($result, 0, 32);
            $data = openssl_decrypt($enct, 'aes-256-cbc', $key, true, $iv);
            return json_decode($data, true);
        } catch (\Throwable $th) {
            throw $th;
        }
    }
}