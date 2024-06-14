# srfbc: some random feistel-based cryptosystem

import copy
import commons as commons
from random import randint

import helper
    
def srfbc_encrypt(plaintext: list[int], key: list[int]): 
    '''
        - len(plaintext) = commons.block_length
        - len(key) = commons.key_length
    '''
    psinit = helper.plaintext_splitter(plaintext)
    rounds_ks = key_scheduler(key)
    
    ps = psinit
    for i in range(commons.round_count):
        ps = srfbc_round(ps, rounds_ks[i*6:(i+1)*6])
        
    cs = srfbc_transform(ps, rounds_ks[commons.round_count*6:commons.round_count*6+4])
    ciphertext = helper.ciphertext_packer(cs)

    return ciphertext
    
def key_scheduler(key: list[int]):
    '''
        - len(key) = commons.key_length
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
            
        working_key = helper.listbin_cyshift(working_key, commons.key_shift_count)

    for i in range(commons.last_round_key_count):
        round_key = copy.copy(working_key[i*step:(i+1)*step])
        round_keys.append(round_key)
        
    return round_keys
    
def srfbc_round(ps: list[list[int]], ks: list[list[int]]) -> list[list[int]]:
    '''
        - len(ps) = 4 * 16
        - len(ks) = 6 * 16
    '''
    step1 = helper.listbin_mul(ps[0], ks[0])
    step2 = helper.listbin_add(ps[1], ks[1])
    step3 = helper.listbin_add(ps[2], ks[2])
    step4 = helper.listbin_add(ps[3], ks[3])
    step5 = helper.listbin_xor(step1, step3)
    step6 = helper.listbin_xor(step2, step4)
    step7 = helper.listbin_mul(step5, ks[4])
    step8 = helper.listbin_add(step6, step7)
    step9 = helper.listbin_mul(step8, ks[5])
    step10 = helper.listbin_add(step7, step9)
    step11 = helper.listbin_xor(step1, step9)
    step12 = helper.listbin_xor(step3, step9)
    step13 = helper.listbin_xor(step2, step10)
    step14 = helper.listbin_xor(step4, step10)

    return [step11, step12, step13, step14]

def srfbc_transform(ps: list[list[int]], ks: list[list[int]]) -> list[list[int]]:
    '''
        - len(ps) = 4 * 16
        - len(ks) = 4 * 16
    '''
    step1 = helper.listbin_mul(ps[0], ks[0])
    step2 = helper.listbin_add(ps[1], ks[1])
    step3 = helper.listbin_add(ps[2], ks[2])
    step4 = helper.listbin_mul(ps[3], ks[3])

    return [step1, step2, step3, step4]
    