# srfbc: some random feistel-based cryptosystem

import copy
import commons

################################################################## operators 
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
    
def list_cyclic_shift(p: list[int], count: int, dir='left'):
    if dir == 'left':
        return p[count:] + p[:count]
    else:
        return p[:count] + p[count:]
    
def module_multiply(a: int, b: int):
    return (a * b) % commons.mul_module

def module_add(a: int, b: int):
    return (a + b) % commons.add_module

def list_to_str(l: list[int]):
    return ''.join(map(str, l))

def list_to_num(l: list[int]):
    return int(list_to_str(l), 2)

def num_to_str(n: int, strlen: int):
    return bin(n)[2:].zfill(strlen)

def num_to_list(n: int, listlen: int):
    return list(map(int, list(num_to_str(n, listlen))))

def list_multiply(a: list[int], b: list[int]):
    a_num = list_to_num(a)
    b_num = list_to_num(b)
    
    mul = module_multiply(a_num, b_num)

    return num_to_list(mul, len(a))

def list_addition(a: list[int], b: list[int]):
    a_num = list_to_num(a)
    b_num = list_to_num(b)
    
    mul = module_add(a_num, b_num)

    return num_to_list(mul, len(a))

def list_xor(a: list[int], b: list[int]):
    result = []
    for i in range(len(a)):
        result.append(a[i] ^ b[i])
    return result
    
################################################################## cryptosystem    
def srfbc_encrypt(plaintext: list[int], key: list[int]): 
    '''
    parameters:
        plaintext: 
            - list[int]
            - len(plaintext) = commons.block_length
        key:
            - list[int]
            - len(key) = commons.key_length
    '''
    psinit = plaintext_splitter(plaintext)
    rounds_ks = key_scheduler(key)
    
    ps = psinit
    for i in range(commons.round_count):
        ps = srfbc_round(ps, rounds_ks[i*6:(i+1)*6])
        
    cs = srfbc_transform(ps, rounds_ks[commons.round_count*6:commons.round_count*6+4])
    ciphertext = ciphertext_packer(cs)

    return ciphertext
    
def key_scheduler(key: list[int]):
    '''
    parameters:
        key:
            - list[int]
            - len = commons.key_length
    '''
    working_key = copy.copy(key)
    round_keys = [] # list[list[int]]
    step = commons.round_key_length
    
    rounds_needed_keys = commons.round_key_count * commons.round_count
    turn_keys_count = len(key) // step
    
    for _ in range(rounds_needed_keys // turn_keys_count):
        for i in range(turn_keys_count):
            round_key = copy.copy(working_key[i*step:(i+1)*step])
            round_keys.append(round_key)
            
        working_key = list_cyclic_shift(working_key, commons.key_shift_count)

    for i in range(commons.last_round_key_count):
        round_key = copy.copy(working_key[i*step:(i+1)*step])
        round_keys.append(round_key)
        
    return round_keys
    
def srfbc_round(ps: list[list[int]], ks: list[list[int]]) -> list[list[int]]:
    '''
    parameters:
        ps:
            - list[list[int]]
            - len = 4 * 16
        ks:
            - list[list[int]]
            - len = 6 * 16
    '''
    step1 = list_multiply(ps[0], ks[0])
    step2 = list_addition(ps[1], ks[1])
    step3 = list_addition(ps[2], ks[2])
    step4 = list_addition(ps[3], ks[3])
    step5 = list_xor(step1, step3)
    step6 = list_xor(step2, step4)
    step7 = list_multiply(step5, ks[4])
    step8 = list_addition(step6, step7)
    step9 = list_multiply(step8, ks[5])
    step10 = list_addition(step7, step9)
    step11 = list_xor(step1, step9)
    step12 = list_xor(step3, step9)
    step13 = list_xor(step2, step10)
    step14 = list_xor(step4, step10)

    return [step11, step12, step13, step14]

def srfbc_transform(ps: list[list[int]], ks: list[list[int]]) -> list[list[int]]:
    '''
    parameters:
        ps:
            - list[list[int]]
            - 4 * 16
        ks:
            - list[list[int]]
            - 4 * 16
    '''
    step1 = list_multiply(ps[0], ks[0])
    step2 = list_addition(ps[1], ks[1])
    step3 = list_addition(ps[2], ks[2])
    step4 = list_multiply(ps[3], ks[3])

    return [step1, step2, step3, step4]
    
    