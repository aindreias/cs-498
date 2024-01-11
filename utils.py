from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher import Cipher
from claasp.cipher_modules import neural_network_tests
from claasp.components.permutation_component import Permutation
from crax import create_crax_instance
from ascon_128 import create_ascon_instance
from isap_a_128a import create_isap_instance
from schwaemm_256_128 import create_schwaemm_instance
from photon_beetle_128 import create_photon_beetle_instance

from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.ciphers.permutations.photon_permutation import PhotonPermutation
from claasp.ciphers.permutations.sparkle_permutation import SparklePermutation

from keras.optimizers import Adam
import numpy as np
from os import urandom

## N.B.: diff is an array of bytes of length pt_byte_size!
def create_random_inputs(pt_byte_size: int, key_byte_size: int, nb_samples: int, diff):
    pt_0 = np.frombuffer(urandom(nb_samples*pt_byte_size), dtype=np.uint8).reshape((nb_samples, pt_byte_size))
    pt_1 = pt_0 ^ diff

    labels = np.frombuffer(urandom(nb_samples), dtype=np.uint8); labels = labels & 1
    # label 0 = random, label 1 = real

    num_random_samples = np.sum(labels==0)
    pt_1[labels==0] = np.frombuffer(urandom(num_random_samples*pt_byte_size), dtype=np.uint8).reshape((num_random_samples, pt_byte_size))

    assert(pt_0.shape == pt_1.shape)

    keys = np.frombuffer(urandom(nb_samples*key_byte_size), dtype=np.uint8).reshape((nb_samples, key_byte_size))

    #np.savez_compressed(filename, pt0=pt_0, pt1=pt_1, ks=keys, y=labels)

    return pt_0, pt_1, keys, labels.reshape((nb_samples, 1))

def create_nonce_ad(nonce_byte_size: int, ad_byte_size: int, nb_samples: int, repeat_nonce: int):
    print(repeat_nonce)
    nonce = np.frombuffer(urandom(nb_samples*nonce_byte_size),
                          dtype=np.uint8).reshape((nb_samples, nonce_byte_size)) if (repeat_nonce < 0) else np.full((nb_samples, nonce_byte_size), repeat_nonce.to_bytes(nonce_byte_size), dtype=np.uint8)

    ad = np.frombuffer(urandom(nb_samples*ad_byte_size), dtype=np.uint8).reshape((nb_samples, ad_byte_size))

    return nonce, ad

def make_x_y(cipher: Cipher, plaintext_byte_size, key_byte_size, nb_samples, diff):
    pt0, pt1, ks, y = create_random_inputs(plaintext_byte_size, key_byte_size, nb_samples, diff)

    vectorized_plaintext = pt0.transpose()
    vectorized_keys = ks.transpose()

    ct0 = cipher.evaluate_vectorized([vectorized_plaintext, vectorized_keys])[0]
    ct1 = cipher.evaluate_vectorized([pt1.transpose(), vectorized_keys])[0]

    ## ... Now we have to merge ct0, ct1 and transform them to bits ... ##
    ## ... This method is already implemented in neural_network_tests::create_differential_dataset ... ##

    ct0_bits = np.unpackbits(ct0, axis=1)
    ct1_bits = np.unpackbits(ct1, axis=1)

    x = np.hstack([ct0_bits, ct1_bits])

    return x, y

## Convention: repeat_nonce = -1 => don't repeat the nonce;
## repeat_nonce > 0 : repeat the nonce with this value
def make_x_y_aead(aeadScheme: Cipher, plaintext_byte_size, key_byte_size,
                  nonce_byte_size, ad_byte_size, nb_samples, diff,
                  repeat_nonce=-1):
    
    n0, n1, ks, y = create_random_inputs(nonce_byte_size, key_byte_size, nb_samples, diff)

    ## TODO fix repeat nonce
    pt, ad = create_nonce_ad(plaintext_byte_size, ad_byte_size, nb_samples, repeat_nonce)

    vectorized_plaintext = pt.transpose()
    vectorized_keys = ks.transpose()

    vectorized_nonce_0 = n0.transpose()
    vectorized_nonce_1 = n1.transpose()
    vectorized_ad = ad.transpose()

    ct0 = aeadScheme.evaluate_vectorized([vectorized_plaintext, vectorized_keys, vectorized_nonce_0, vectorized_ad])[0]
    ct1 = aeadScheme.evaluate_vectorized([vectorized_plaintext, vectorized_keys, vectorized_nonce_1, vectorized_ad])[0]

    #print(ct0[0:3])
    #print(ct1[0:3])
    #print(y[0:3])

    ## ... Now we have to merge ct0, ct1 and transform them to bits ... ##
    ## ... This method is already implemented in neural_network_tests::create_differential_dataset ... ##

    ct0_bits = np.unpackbits(ct0, axis=1)
    ct1_bits = np.unpackbits(ct1, axis=1)

    x = np.hstack([ct0_bits, ct1_bits])

    return x, y

def make_x_y_perm(perm: Cipher, plaintext_byte_size, nb_samples, diff):
    pt0, pt1, _ , y = create_random_inputs(plaintext_byte_size, 0, nb_samples, diff)

    vectorized_plaintext = pt0.transpose()

    ct0 = perm.evaluate_vectorized([vectorized_plaintext])[0]
    ct1 = perm.evaluate_vectorized([vectorized_plaintext])[0]

    ## ... Now we have to merge ct0, ct1 and transform them to bits ... ##
    ## ... This method is already implemented in neural_network_tests::create_differential_dataset ... ##

    ct0_bits = np.unpackbits(ct0, axis=1)
    ct1_bits = np.unpackbits(ct1, axis=1)

    x = np.hstack([ct0_bits, ct1_bits])

    return x, y

def evaluate_permutation(perm: Cipher, plaintext_byte_size, word_bit_size, nb_samples, batch_size, nb_epochs, diff):
    ## ... Dataset creation ... ##

    print("Creating training data ...")
    x, y = make_x_y_perm(perm, plaintext_byte_size, nb_samples, diff)

    print("Creating validation data ...")
    x_eval, y_eval = make_x_y_perm(perm, plaintext_byte_size, nb_samples//10, diff)

    print("DataGen done!")

    ## ... Now we have to create a Residual Network ... ##
    
    total_input_size = perm.output_bit_size*2 # 2 ciphertexts are expected
    neural_network = neural_network_tests.make_resnet(word_size = int(word_bit_size), input_size = total_input_size, reg_param=10**(-4), depth=1)
    neural_network.compile(optimizer=Adam(amsgrad=True, learning_rate=10 ** (-4), weight_decay=True), loss='mse', metrics=['acc'])

    ## ... and train it ... ##

    h = neural_network.fit(x, y, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_eval, y_eval))
    acc = np.max(h.history["val_acc"])
    print(f'Highest validation accuracy at :{acc}')

def evaluate_permutation_experimental(perm: Cipher, plaintext_byte_size, word_bit_size, nb_samples, batch_size, nb_epochs, diff):
    ## ... Create a Residual Network ... ##
    
    total_input_size = perm.output_bit_size*2 # 2 ciphertexts are expected
    neural_network = neural_network_tests.make_resnet(word_size = int(word_bit_size), input_size = total_input_size, reg_param=10**(-4))
    neural_network.compile(optimizer=Adam(amsgrad=True, learning_rate=3 * 10 ** (-4), weight_decay=True), loss='bce', metrics=['acc'])

    ## ... Train it ... ##
    for i in range(3):
        print(f"Creating dataset {i} ...")
        x, y = make_x_y_perm(perm, plaintext_byte_size, int(nb_samples*1.1), diff)

        print(f"Fitting {i} ... ")
        h = neural_network.fit(x, y, validation_split = 0.1, initial_epoch = i*nb_epochs, epochs=(i+1)*nb_epochs, batch_size=batch_size)
    
    print("Creating random test data ... ")
    x, y = make_x_y_perm(perm, plaintext_byte_size, 100_000, diff)
    print("Done. Now evaluating ... ")
    res = neural_network.evaluate(x, y)
    print("Test loss and test accuracy: ", res)

def evaluate_cipher(cipher: Cipher, plaintext_byte_size, key_byte_size, word_bit_size, nb_samples, batch_size, nb_epochs, diff):

    ## ... Dataset creation ... ##

    print("Creating training data ...")
    x, y = make_x_y(cipher, plaintext_byte_size, key_byte_size, nb_samples, diff)

    print("Creating validation data ...")
    x_eval, y_eval = make_x_y(cipher, plaintext_byte_size, key_byte_size, nb_samples//10, diff)

    print("DataGen done!")

    ## ... Now we have to create a Residual Network ... ##
    
    total_input_size = cipher.output_bit_size*2 # 2 ciphertexts are expected
    neural_network = neural_network_tests.make_resnet(word_size = int(word_bit_size), input_size = total_input_size)
    neural_network.compile(optimizer=Adam(amsgrad=True), loss='mse', metrics=['acc'])

    ## ... and train it ... ##

    h = neural_network.fit(x, y, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_eval, y_eval))
    acc = np.max(h.history["val_acc"])
    print(f'Highest validation accuracy at :{acc}')

def evaluate_aead(aeadScheme: Cipher, plaintext_byte_size, key_byte_size,
                  nonce_byte_size, ad_byte_size, word_bit_size,
                  nb_samples, batch_size, nb_epochs, diff,
                  repeat_nonce=-1):
    
    ## ... Dataset creation ... ##

    print("Creating training data ...")
    x, y = make_x_y_aead(aeadScheme, plaintext_byte_size, key_byte_size,
                         nonce_byte_size, ad_byte_size, nb_samples, diff,
                         repeat_nonce)

    print("Creating validation data ...")
    x_eval, y_eval = make_x_y_aead(aeadScheme, plaintext_byte_size, key_byte_size,
                         nonce_byte_size, ad_byte_size, nb_samples//10, diff,
                         repeat_nonce)

    print("DataGen done!")

    ## ... Now we have to create a Residual Network ... ##
    
    total_input_size = aeadScheme.output_bit_size*2 # 2 ciphertexts are expected
    neural_network = neural_network_tests.make_resnet(word_size = int(word_bit_size), input_size = total_input_size)
    neural_network.compile(optimizer=Adam(amsgrad=True), loss='mse', metrics=['acc'])

    ## ... and train it ... ##

    h = neural_network.fit(x, y, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_eval, y_eval))
    acc = np.max(h.history["val_acc"])
    print(f'Highest validation accuracy at :{acc}')

def evaluate_speck():
    speck = SpeckBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=6)

    speck_diff_0 = [0,0,0x00, 0x80, 0x80, 0, 0, 0]
    #speck_diff_1 = [0,0,0x00, 0x80, 0x00, 0, 0, 0]
    #speck_diff_2 = [0,0,0x04, 0x80, 0x80, 0, 0, 0]
    #speck_diff_3 = [0,0,0x00, 0xc0, 0x00, 0, 0, 0]

    print("Evaluating SPECK-64/128 ...")

    evaluate_cipher(speck, plaintext_byte_size=8, key_byte_size=16, word_bit_size=32,
                    nb_samples = 500_000, batch_size = 5_000, nb_epochs = 20,
                    diff=speck_diff_0)
    
def evaluate_crax():
    crax = create_crax_instance(number_of_rounds=2)

    #crax_diff_0 = [0,0,0,0,0x4000,0x0000,0x0000,0x0000] ## NOT a valid diff

    # 0x40_00_00_00_00_00_00_00
    crax_diff_1 = [0x40, 0, 0, 0, 0, 0, 0, 0]

    print("Evaluating CRAX-S-10 ... ")

    print(crax.number_of_rounds)

    evaluate_cipher(crax, plaintext_byte_size=8, key_byte_size=16, word_bit_size=32,
                    nb_samples=100_000, batch_size=10_000, nb_epochs=20,
                    diff=crax_diff_1)
    
def evaluate_ascon_128(plaintext_block_count=1, ad_block_count=1, reuse_nonce=-1):
    ascon = create_ascon_instance(plaintext_block_count, ad_block_count)

    ascon_diff_0 = [0,0,0,0,0,0x0002,0x0000,0x0000] ## NOT a valid diff

    # 0x00_40_00_00_00_00_00_00
    ascon_diff_1 = [0, 0x40, 0, 0, 0, 0, 0, 0]

    # 0x2 # TODO: rerun ASCON INPUT DIFF FOR 2PT, 1 AD case
    ascon_diff_2 = [0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0x2]
    
    # 0x04_00_00 _00_00_00_00_00_04_00_00
    # Nonce difference
    nonce_diff_0 = [0, 0, 0, 0, 0, 0x04, 0, 0,
                    0, 0, 0, 0, 0, 0x04, 0, 0]

    setting = f"nonce misuse (nonce = {reuse_nonce})" if reuse_nonce > 0 else "nonce respecting" 

    print(f"Evaluating ASCON_128 with {plaintext_block_count} PT block(s) and {ad_block_count} AD block(s). Setting: {setting}")

    pt_bytes = plaintext_block_count * 8
    ad_bytes = ad_block_count * 8

    if (pt_bytes == 0): pt_bytes = 1
    if (ad_bytes == 0): ad_bytes = 1

    evaluate_aead(ascon, plaintext_byte_size=pt_bytes, key_byte_size=16,
                  nonce_byte_size=16, ad_byte_size=ad_bytes, word_bit_size=32,
                  nb_samples=700_000, batch_size=70_000, nb_epochs=30,
                  diff=nonce_diff_0, repeat_nonce=reuse_nonce)
    
def evaluate_schwaemm(plaintext_block_count=1, ad_block_count=1, reuse_nonce=-1):
    schwaemm = create_schwaemm_instance(plaintext_block_count, ad_block_count)

    schwaemm_diff_0 = [0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,
                       0,0,0,0, 0x2000, 0x0000, 0x0000, 0x0002]

    setting = f"nonce misuse (nonce = {reuse_nonce})" if reuse_nonce > 0 else "nonce respecting" 

    print(f"Evaluating SCHWAEMM-256-128  with {plaintext_block_count} PT block(s) and {ad_block_count} AD block(s). Setting: {setting}... ")

    pt_bytes = plaintext_block_count * 32
    ad_bytes = ad_block_count * 32

    if (pt_bytes == 0): pt_bytes = 1
    if (ad_bytes == 0): ad_bytes = 1

    evaluate_aead(schwaemm, plaintext_byte_size=pt_bytes, key_byte_size=16,
                  nonce_byte_size=16, ad_byte_size=ad_bytes, word_bit_size=32,
                  nb_samples=10_000, batch_size=200, nb_epochs=20,
                  diff=schwaemm_diff_0, repeat_nonce=reuse_nonce)

def evaluate_isap(plaintext_block_count=1, ad_block_count=1, reuse_nonce=-1):
    isap = create_isap_instance(plaintext_block_count, ad_block_count)

    isap_diff_0 = [0,0,0,0,0xfa50,0x5562,0xe6f8,0xe83b]

    setting = f"nonce misuse (nonce = {reuse_nonce})" if reuse_nonce > 0 else "nonce respecting" 

    print(f"Evaluating ISAP-A-128A with {plaintext_block_count} PT block(s) and {ad_block_count} AD block(s). Setting: {setting}... ")

    pt_bytes = plaintext_block_count * 8
    ad_bytes = ad_block_count * 8

    if (pt_bytes == 0): pt_bytes = 1
    if (ad_bytes == 0): ad_bytes = 1

    evaluate_aead(isap, plaintext_byte_size=pt_bytes, key_byte_size=16,
                  nonce_byte_size=16, ad_byte_size=ad_bytes, word_bit_size=32,
                  nb_samples=1_000, batch_size=50, nb_epochs=20,
                  diff=isap_diff_0, repeat_nonce=reuse_nonce)
    
def evaluate_photon_beetle(plaintext_block_count=1, ad_block_count=1, reuse_nonce=-1):
    pb = create_photon_beetle_instance(plaintext_block_count, ad_block_count)

    ## TODO: replace this diff with a "real" one
    pb_diff_0 = [0,0,0,0,0,0,0,0,0,0,0,0,0xfa50,0x5562,0xe6f8,0xe83b]

    setting = f"nonce misuse (nonce = {reuse_nonce})" if reuse_nonce > 0 else "nonce respecting" 

    print(f"Evaluating PHOTON-Beetle-AEAD[128] with {plaintext_block_count} PT block(s) and {ad_block_count} AD block(s). Setting: {setting}... ")

    pt_bytes = plaintext_block_count * 16
    ad_bytes = ad_block_count * 16

    if (pt_bytes == 0): pt_bytes = 1
    if (ad_bytes == 0): ad_bytes = 1

    evaluate_aead(pb, plaintext_byte_size=pt_bytes, key_byte_size=16,
                  nonce_byte_size=16, ad_byte_size=ad_bytes, word_bit_size=32,
                  nb_samples=1_000, batch_size=50, nb_epochs=20,
                  diff=pb_diff_0, repeat_nonce=reuse_nonce)

# word_size = 64
def evaluate_permutation_ASCON(number_of_rounds=12):
    p_ascon = AsconPermutation(number_of_rounds)

    p_ascon_diff_0 = [0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0x0002,0,0,0,0x0002,0,
                    0,0,0,0,0,0,0,0]
    
    # Real ascon diff: (reaching round 4/12):
    #0x0000_0000_0002_0000_0000_0000_0002_0000
    #0x0000_0000_0000_0000_0000_0000_0000_0000 
    
    evaluate_permutation(p_ascon, plaintext_byte_size=40, word_bit_size=64,
                         nb_samples=100_000, batch_size=5_000, nb_epochs=20,
                         diff=p_ascon_diff_0)

def evaluate_permutation_PHOTON():
    p_photon = PhotonPermutation()

    ## Made-up difference:
    p_photon_diff_0 = [0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0x8000,0,0,0,0,
                    0,0,0,0,0,0,0,0]
    
    ## ...  0000 ... 
    ## 0000_0000_0000_0000_0000_0000_0000_0001
    ## 0000_0000_0000_0000_0000_0000_0000_0000

    p_photon_diff_1 = [0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0x0001,
                    0,0,0,0,0,0,0,0]
    
    evaluate_permutation(p_photon, plaintext_byte_size=32, word_bit_size=4,
                         nb_samples=200_000, batch_size=1_000, nb_epochs=50,
                         diff=p_photon_diff_1)

# word size 32
def evaluate_permutation_SPARKLE():
    p_sparkle = SparklePermutation(number_of_blocks=4, number_of_steps=1)

    print("Evaluating SPARKLE-p ... ")

    ##8000_0000_4000_0000
    p_sparkle_diff_0 = [0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0x8000,0,0x4000,0]

    evaluate_permutation(p_sparkle, plaintext_byte_size=32, word_bit_size=32,
                         nb_samples=250_000, batch_size=2_500, nb_epochs=15,
                         diff=p_sparkle_diff_0)

## Ciphers:
#evaluate_speck()
#evaluate_crax()
#evaluate_ascon_128()
#evaluate_schwaemm()
#evaluate_isap()
#evaluate_photon_beetle()

## Permutations:
#evaluate_permutation_ASCON(number_of_rounds=12)
#evaluate_permutation_PHOTON()
#evaluate_permutation_SPARKLE()