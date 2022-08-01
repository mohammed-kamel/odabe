#! /usr/bin/python3
'''
To test the odabe execution time
usage: ./test.py 20 5 
where (20) is number of each iterations per attribute, and (5) is the number of attributes.
Author: Mohammed B. M. Kamel 

'''

import subprocess
import sys
import os
import random


time_file_path = {
'dabe':'dabe_time.txt',
'odabe encryptor':'odabe_encryptor_time.txt',
'odabe computational node':'odabe_computationalnode_time.txt'
}

attributes = ['one', 'two', 'three', 'four', 'five']
operators = ['and', 'or']

def remove_files():
    if os.path.exists(time_file_path['dabe']):
        os.remove(time_file_path['dabe'])
    if os.path.exists(time_file_path['odabe encryptor']):
        os.remove(time_file_path['odabe encryptor'])


def set_loop():
    if(sys.argv[1].isdigit()): 
        print('loop value has been set to ', sys.argv[1])
        return int(sys.argv[1])
    else:
        print('no loop value has been provided. it has been set to 5. i.e., 5 times redo the execution.')
        return 20


def caculate_average_time(loop):
    if os.path.exists(time_file_path['dabe']): 
        dabe_time_file = open(time_file_path['dabe'], 'r')
        dabe_time = 0.0
        for i in range(loop):
            dabe_time += float(dabe_time_file.readline())
        print("[x] Average Execution Time (original DABE) \t: ", dabe_time/loop)

    if os.path.exists(time_file_path['odabe encryptor']):
        dabe_time_file = open(time_file_path['odabe encryptor'], 'r')
        odabe_enc_time = 0.0
        for i in range(loop):
            odabe_enc_time += float(dabe_time_file.readline())
        print("[x] Average Execution Time (ODABE - encryptor) \t: ", odabe_enc_time/loop)

def generate_access_structure(n):
    if n<=0:
        return n
    access_structure = attributes[0] + ' '
    for a in range(1,n):
        access_structure += random.choice(operators) +' '+ attributes[a] + ' '
    access_structure = access_structure[:len(access_structure)- 1]
    return access_structure

def main():
    loop = set_loop()
    if(len(sys.argv) == 2) and (sys.argv[2].isdigit()):
        attr_numbers = int(sys.argv[2])
    else:
        attr_numbers = 5
    for i in range(1, len(attributes) + 1):
        remove_files()
        access_structure = generate_access_structure(i)
        print('\n\nTesting {} attribute(s)'.format(i))
        print('************************************')
        print('[x] Generated access structure = ', access_structure)
        for _ in range(loop):
            subprocess.run(['./singlenode_v3_8may22.py', access_structure])
        caculate_average_time(loop)
        print('************************************')

if __name__ == "__main__":
    main()


