import commons
from random import randint

def get_random_listbin(binlen):
    result = []
    for i in range(binlen):
        result.append(randint(0, 1))
    return result

def plaintext_splitter(plaintext: list[int]):
    step = len(plaintext) // 4
    return [plaintext[0:step], 
            plaintext[step:2*step], 
            plaintext[2*step:3*step], 
            plaintext[3*step:4*step]]

def ciphertext_packer(cs: list[list[int]]):
    result = []
    for i in range(len(cs)):
        for j in range(len(cs[i])):
            result.append(cs[i][j])
    return result
    
def listbin_cyshift(p: list[int], count: int, dir='left'):
    if dir == 'left':
        return p[count:] + p[:count]
    else:
        return p[:count] + p[count:]

def listbin_to_str(l: list[int]):
    return ''.join(map(str, l))

def listbin_to_int(l: list[int]):
    return int(listbin_to_str(l), 2)

def int_to_strbin(n: int, strlen: int):
    return bin(n)[2:].zfill(strlen)

def int_to_listbin(n: int, listlen: int):
    return list(map(int, list(int_to_strbin(n, listlen))))

def mod_add(a: int, b: int):
    return (a + b) % commons.add_module

def mod_mul(a: int, b: int):
    return (a * b) % commons.mul_module

def listbin_add(a: list[int], b: list[int]):
    a_num = listbin_to_int(a)
    b_num = listbin_to_int(b)
    
    mul = mod_add(a_num, b_num)

    return int_to_listbin(mul, len(a))

def listbin_xor(a: list[int], b: list[int]):
    result = []
    for i in range(len(a)):
        result.append(a[i] ^ b[i])
    return result

def listbin_mul(a: list[int], b: list[int]):
    a_num = listbin_to_int(a)
    b_num = listbin_to_int(b)
    
    mul = mod_mul(a_num, b_num)

    return int_to_listbin(mul, len(a))