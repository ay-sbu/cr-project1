from random import randint
from srfbc import srfbc_encrypt
import commons

def num_to_str(n: int, strlen: int):
    return bin(n)[2:].zfill(strlen)

def num_to_list(n: int, listlen: int):
    return list(map(int, list(num_to_str(n, listlen))))

def list_to_str(l: list[int]):
    return ''.join(map(str, l))

def list_to_num(l: list[int]):
    return int(list_to_str(l), 2)

def get_random_bin_list(binlen):
    result = []
    for i in range(binlen):
        result.append(randint(0, 1))
    return result

def test_given():
    plaintext_num = 0x0011223344556677
    plaintext = num_to_list(plaintext_num, commons.block_length)
    
    key_num = 0x8123456789abcdeffedcba9876543218
    key = num_to_list(key_num, commons.block_length)

    ciphertext = srfbc_encrypt(plaintext, key)
    
    print(plaintext)
    print(key)
    print(ciphertext)
    print(hex(list_to_num(ciphertext)))
    

def test_01():
    plaintext = get_random_bin_list(commons.block_length)
    key = get_random_bin_list(commons.key_length)
    ciphertext = srfbc_encrypt(plaintext, key)
    
    print(plaintext)
    print(key)
    print(ciphertext)


if __name__ == "__main__":
    # test_01()
    test_given()
    