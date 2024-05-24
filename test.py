from random import randint
from srfbc import srfbc_encrypt
import commons

def get_random_bin_list(binlen):
    result = []
    for i in range(binlen):
        result.append(randint(0, 1))
    return result

def test_01():
    plaintext = get_random_bin_list(commons.block_length)
    key = get_random_bin_list(commons.key_length)
    ciphertext = srfbc_encrypt(plaintext, key)
    
    print(plaintext)
    print(key)
    print(ciphertext)


if __name__ == "__main__":
    test_01()
    