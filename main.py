################################################################################
#                Skeleton script for a DFA attack against AES                  #
################################################################################
#                                                                              #
# Sichere Implementierung kryptographischer Verfahren WS 2013-2014             #
# Technische Universitaet Muenchen                                             #
# Institute for Security in Information Technology                             #
# Prof. Dr.-Ing. Georg Sigl                                                    #
#                                                                              #
################################################################################

############################## IMPORT MODULES ##################################

import csv
import os
import student
import numpy
import argparse
import time
import test_key
import copy


def main(pairs_path='./'):

    ################### LOAD CORRECT AND FAULTY CIPHERTEXTS  #######################

    plaintexts = []
    correct_ciphertexts = []
    faulty_ciphertexts = []

    # You might want to change the csv filename here
    csv_reader_faulty_pairs = csv.reader(
        open(os.path.join(pairs_path, 'faulty_pairs.csv'), 'r'), delimiter=',')
    for row in csv_reader_faulty_pairs:
        plaintexts.append([int(row[0][i:i + 2], 16)
                           for i in range(2, len(row[0]), 2)])
        correct_ciphertexts.append([int(row[1][i:i + 2], 16)
                                    for i in range(2, len(row[1]), 2)])
        faulty_ciphertexts.append([int(row[2][i:i + 2], 16)
                                   for i in range(2, len(row[2]), 2)])

    # Save one cipher/plaintext pair in case the input lists get modified inplace
    test_plain = copy.copy(plaintexts[0])
    test_cipher = copy.copy(correct_ciphertexts[0])

    ############################### PERFORM DFA ####################################
    t = time.perf_counter()
    last_round_key = student.perform_dfa(
        correct_ciphertexts, faulty_ciphertexts)
    consumed = time.perf_counter() - t
    print('Execution time: {}s'.format(consumed))

    # Test result
    if test_key.test_key(last_round_key, test_plain, test_cipher):
        result = True
        print("Congratulations! Your key is correct.")
    else:
        result = False
        print("Not only the ciphertexts are faulty, your key is too.")
    ############################# OUTPUT RESULTS ###################################
    print("Key guess:")
    print(last_round_key)
    key_hex = ["{:02x}".format(last_round_key[i])
               for i in range(len(last_round_key))]
    print("Hex: " + ' '.join(key_hex))
    print("Writing key guess to key.txt...")
    keyF = open("./key.txt", "w")
    writer = csv.writer(keyF)
    writer.writerow(key_hex)
    print("Done.")
    keyF.close()

    with open("./report.txt", "w") as result_file:
        result_file.write("{}, {}".format(result, consumed)) # attack success, elapsed time



if __name__ == '__main__':
    ############################ DEFINE PARAMETERS #################################
    parser = argparse.ArgumentParser(
        description="Main file of the fourth exercise for the SIKA lecture.")
    parser.add_argument("--pairs-path", dest="pairs_path", default='./',
                        help="Path to the faulty pairs. Default='./'", type=str)

    args = parser.parse_args()

    pairs_path = args.pairs_path

    main(pairs_path=pairs_path)
