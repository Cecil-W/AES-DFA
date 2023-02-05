#!/usr/bin/env python
import sys, random, argparse
import logging

log = logging.getLogger("AES")
verbose = False

Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = Sbox[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


# learnt from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # please see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def round(state_matrix, key_matrix):
    sub_bytes(state_matrix)
    log.debug("State after Sub Bytes:\t\t0x%0.32X" % matrix2text(state_matrix))

    shift_rows(state_matrix)
    log.debug("State after Shift Rows:\t0x%0.32X" % matrix2text(state_matrix))

    mix_columns(state_matrix)
    log.debug("State after Mix Columns:\t0x%0.32X" % matrix2text(state_matrix))

    add_round_key(state_matrix, key_matrix)
    log.debug("State after Add Round Key:\t0x%0.32X" % matrix2text(state_matrix))


def text2matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix


def matrix2text(matrix):
    text = 0
    for i in range(4):
        for j in range(4):
            text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return text


class AES:
    def __init__(self, master_key, fault_round, fault_bytes, fault_type):
        self.change_key(master_key)
        self.fRound = fault_round
        self.fBytes = fault_bytes
        self.fType = fault_type

    def change_key(self, master_key):
        self.round_keys = text2matrix(master_key)

        for i in range(4, 4 * 11):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = self.round_keys[i - 4][0] \
                       ^ Sbox[self.round_keys[i - 1][1]] \
                       ^ Rcon[i // 4]
                self.round_keys[i].append(byte)

                for j in range(1, 4):
                    byte = self.round_keys[i - 4][j] \
                           ^ Sbox[self.round_keys[i - 1][(j + 1) % 4]]
                    self.round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j] \
                           ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)

        for i in range(11):
            log.debug("Round Key %i:\t\t\t0x%0.32X" % (i, matrix2text(self.round_keys[4 * i: 4 * (i + 1)])))

    def encrypt(self, plaintext):
        self.plain_state = text2matrix(plaintext)

        add_round_key(self.plain_state, self.round_keys[:4])

        log.debug("State after Add Round Key:\t0x%0.32X" % matrix2text(self.plain_state))

        for i in range(1, 10):
            round(self.plain_state, self.round_keys[4 * i: 4 * (i + 1)])

            if i == self.fRound:
                for b in self.fBytes:
                    if self.fType == 'RND':
                        self.plain_state[b // 4][b % 4] = random.randint(0, 255)
                    else:
                        self.plain_state[b // 4][b % 4] = 0
                log.debug("State after introducing error:\t0x%0.32X" % matrix2text(self.plain_state))

            log.debug("State after round %d:\t\t0x%0.32X" % (i, matrix2text(self.plain_state)))

        sub_bytes(self.plain_state)
        log.debug("State after Sub Bytes:\t\t0x%0.32X" % matrix2text(self.plain_state))

        shift_rows(self.plain_state)
        log.debug("State after Shift Rows:\t0x%0.32X" % matrix2text(self.plain_state))

        add_round_key(self.plain_state, self.round_keys[40:])
        log.debug("State after Add Round Key:\t0x%0.32X" % matrix2text(self.plain_state))

        return matrix2text(self.plain_state)


if __name__ == '__main__':
    # plaintext = 0x3243f6a8885a308d313198a2e0370734
    # plaintext = random.getrandbits(128)

    parser = argparse.ArgumentParser(description='Run the AES encryption with specified byte faults.')
    parser.add_argument('-r', '--round', help='The round AFTER which to introduce an error', type=int, default=7)
    parser.add_argument('-b', '--byte',
                        help='The byte(s) to modify, multiple bytes must be written with spaces inbetween', type=int,
                        default=[0], nargs='+')
    parser.add_argument('-m', '--model',
                        help='The type of error to introduce, RND for replacing the specified byte(s) with a random'
                             '  value, NULL for setting the byte(s) to zero',
                        default="RND")
    parser.add_argument('-n', '--npairs', help='How many Correct / Faulty pairs to generate', type=int, default=2)
    parser.add_argument('-k', '--key', help='The key to use, specified as a hex number in the format 0xABCDEF...',
                        default="0x0123456789ABCDEF")
    parser.add_argument('-v', '--verbose', help='Pass a non-zero value to activate verbose mode', action="store_true")
    parser.add_argument('--save-csv', dest="save_csv", action="store_true", help="Store generated faulty pairs in 'faulty_pairs.csv'.")
    parser.add_argument('--csv-filename',dest="csv_filename", type=str, help="Store generated faulty pairs in 'faulty_pairs.csv'.", default='./faulty_pairs.csv')
    args = parser.parse_args()

    if vars(args)['verbose']:
        log.setLevel(logging.DEBUG)

    my_AES_correct = AES(int(vars(args)['key'], base=16), 0, 0, 0)
    my_AES_faulty = AES(int(vars(args)['key'], base=16), vars(args)['round'], vars(args)['byte'], vars(args)['model'])

    # save faulty pairs
    with open(args.csv_filename, "w") as fp_file:
        for n in range(vars(args)['npairs']):
            plaintext = random.getrandbits(128)
            encrypted_correct = my_AES_correct.encrypt(plaintext)
            encrypted_faulty = my_AES_faulty.encrypt(plaintext)

            print("0x%0.32X,0x%0.32X,0x%0.32X" % (plaintext, encrypted_correct, encrypted_faulty))
            if args.save_csv:
                # for each tuple of (plain - correct - faulty)
                fp_file.write("0x%0.32X,0x%0.32X,0x%0.32X" % (plaintext, encrypted_correct, encrypted_faulty) + "\n")