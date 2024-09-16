# -*- Mode: Python; tab-width: 4; coding: utf8 -*-
"""
DFA attack against AES.

Please implement your attack in the function perform_dfa()
"""

import numpy as np

# AES Routines

# AES Inverted S-box
rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
         0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
         0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
         0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
         0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
         0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
         0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
         0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
         0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
         0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
         0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
         0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
         0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
         0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
         0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
         0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
         0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
         0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
         0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
         0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
         0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
         0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
         0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
         0x21, 0x0c, 0x7d]


def invSubBytes(in_val):
    """
    Perform SubBytes operation on one byte using rsbox
    :param int in_val: Input Byte
    :return int: substituted byte
    """
    out_val = rsbox[in_val]

    return out_val


def gfmul256(a, b):
    """
    Perform multiplication in Galois field.
    :param int a:
    :param int b:
    :return: a * b in GF(2^8)
    """
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def mixColumn(in_column):
    """
    Perform mixColumn operation on a 4-element array (column)
    :param in_column: 4-element list or np.array with 4 elements
    :return list: the mixed column
    """
    v0, v1, v2, v3 = in_column

    out_column = [
        gfmul256(v0, 2) ^ gfmul256(v1, 3) ^ v2 ^ v3,
        v0 ^ gfmul256(v1, 2) ^ gfmul256(v2, 3) ^ v3,
        v0 ^ v1 ^ gfmul256(v2, 2) ^ gfmul256(v3, 3),
        gfmul256(v0, 3) ^ v1 ^ v2 ^ gfmul256(v3, 2),
    ]

    return out_column


####################### IMPLEMENT YOUR DFA ATTACK BELOW  #######################


def perform_dfa(correct_ciphertexts, faulty_ciphertexts):
    key = np.zeros(16, dtype=np.uint8)
    # ...
    c = np.array(correct_ciphertexts, dtype=np.uint8)
    f = np.array(faulty_ciphertexts, dtype=np.uint8)

    # choose a list of lists for debugging purposes, so it can hold multiple solutions for each byte
    solutions = []
    for _ in range(16):
        solutions.append([])

    # finding canditates for the first column
    solve_column(c, f, solutions, 10, 13, 0, 7)
    # second column
    solve_column(c, f, solutions, 1, 4, 11, 14)
    # third column
    solve_column(c, f, solutions, 8, 15, 2, 5)
    # fourth column
    solve_column(c, f, solutions, 3, 6, 9, 12)

    for index, value in enumerate(solutions):
        key[index] = value[0]  # let's hope we only got 1 solution in the list

    return key


def solve_column(c, f, sol, index_0, index_1, index_2, index_3):
    """
    c = list of correct cipher texts for two pair   \n
    f = list of faulty cipher texts for two pair    \n
    sol = 2d list in which the solution gets saved  \n

    ### index_i ###
    index of the byte in the roundkey, take care entry in the state gets multiplied by 2 or 3
    and assign them to index 2 and 3
    
    example:
    ```
    a_i(index_0) = a_i(index_1)
    a_i(index_0) = a_i(index_1)
    a_i(index_2) = 2 * a_i(index_0)
    a_i(index_3) = 3 * a_i(index_0)
    ```
    """
    # 'ki' are the hypotheses for key byte with index_i
    for k0 in range(256):
        a_0 = a_i(c[0, index_0], k0, f[0, index_0])
        for k1 in range(256):
            a_1 = a_i(c[0, index_1], k1, f[0, index_1])
            if a_0 != a_1:  # if a byte pair doesnt satisfy the equation we skip this k1
                continue
            # now we can check with the second faulty pair
            a_0_second = a_i(c[1, index_0], k0, f[1, index_0])
            a_1_second = a_i(c[1, index_1], k1, f[1, index_1])
            if a_0_second != a_1_second:
                continue
            # now we add the equation for the a_i that is worth 2 F_i
            for k2 in range(256):
                a_2 = a_i(c[0, index_2], k2, f[0, index_2])
                a_2_second = a_i(c[1, index_2], k2, f[1, index_2])
                if (a_2 != gfmul256(a_0, 2)) or (a_2_second != gfmul256(a_0_second, 2)):
                    continue
                # now for the equation which contains the * 3
                for k3 in range(256):
                    a_3 = a_i(c[0, index_3], k3, f[0, index_3])
                    a_3_second = a_i(c[1, index_3], k3, f[1, index_3])
                    if (a_3 != gfmul256(a_0, 3)) or (
                        a_3_second != gfmul256(a_0_second, 3)
                    ):
                        continue
                    # seems like these hypotheses passed all the continues so we can save them
                    # hopefully they are the only ones
                    sol[index_0].append(k0)
                    sol[index_1].append(k1)
                    sol[index_2].append(k2)
                    sol[index_3].append(k3)


def a_i(c_i, k, f_i):
    """
    calculates 'a' with SR applied for a byte 'k'
    c_i: cipher text byte i
    k: key byte i
    f_i: faulty cipher text byte i
    """
    return invSubBytes(c_i ^ k) ^ invSubBytes(f_i ^ k)
