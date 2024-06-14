from random import randint
from srfbc import srfbc_encrypt
import commons as commons

import helper

def test_given():
    plaintext_num = 0x0011223344556677
    plaintext = helper.int_to_listbin(plaintext_num, commons.block_length)
    
    key_num = 0x8123456789abcdeffedcba9876543218
    key = helper.int_to_listbin(key_num, commons.block_length)

    ciphertext = srfbc_encrypt(plaintext, key)
    
    print(plaintext)
    print(key)
    print(ciphertext)
    print(hex(helper.listbin_to_int(ciphertext)))
    

def test_random():
    plaintext = helper.get_random_listbin(commons.block_length)
    key = helper.get_random_listbin(commons.key_length)
    ciphertext = srfbc_encrypt(plaintext, key)
    
    print(plaintext)
    print(key)
    print(ciphertext)


if __name__ == "__main__":
    # test_random()
    test_given()
    