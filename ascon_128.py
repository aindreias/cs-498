from claasp.utils.utils import get_inputs_parameter
from claasp.DTOs.component_state import ComponentState
from claasp.cipher import Cipher

## Code copied from ascon_base.sage ##

from claasp.ciphers.permutations.ascon_permutation import WORD_NUM, WORD_SIZE, LINEAR_LAYER_ROT, PARAMETERS_CONFIGURATION_LIST

# input size: 320 bits
# code modified from already-existing CLAASP code
def ASCON_WRAPPER(cipher: Cipher, input:ComponentState, number_of_rounds):
    state = []
    for i in range(WORD_NUM):
        p = ComponentState(input.id, [[k + i * WORD_SIZE for k in range(WORD_SIZE)]])
        state.append(p)

    # round function
    for r in range(12 - number_of_rounds, 12):
        # initial current round element
        cipher.add_round()

        # round parameter
        ci = 0xf0 - r * 0x10 + r * 0x1

        # round function
        state = round_function(cipher, state, ci)

        # round output
        inputs = []
        for i in range(WORD_NUM):
            inputs.append(state[i])
        ids, pos = get_inputs_parameter(inputs)

        cipher.add_round_output_component(ids, pos, 320)

    ## Now to rebuild the state into the bigger chunk:
    state_id, state_pos = get_inputs_parameter(state[i] for i in range(WORD_NUM))
    cipher.add_concatenate_component(state_id, state_pos, 320)
    reconstructed_state = ComponentState([cipher.get_current_component_id()], [list(range(320))])

    return reconstructed_state


def round_function(cipher, state, ci):
    # add round constant
    # W2 = W2 ^ ci
    cipher.add_constant_component(WORD_SIZE, ci)
    c = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])
    inputs_id, inputs_pos = get_inputs_parameter([state[2], c])
    cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
    state[2] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    # substitution layer
    # S[0] ^= S[4]
    inputs_id, inputs_pos = get_inputs_parameter([state[0], state[4]])
    cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
    state[0] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    # S[4] ^= S[3]
    inputs_id, inputs_pos = get_inputs_parameter([state[4], state[3]])
    cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
    state[4] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    # S[2] ^= S[1]
    inputs_id, inputs_pos = get_inputs_parameter([state[2], state[1]])
    cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
    state[2] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    # T = [(~S[i]) & S[(i + 1) % 5] for i in range(5)]
    T = []
    for i in range(WORD_NUM):
        cipher.add_NOT_component(state[i].id, state[i].input_bit_positions, WORD_SIZE)
        s = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([s, state[(i + 1) % WORD_NUM]])
        cipher.add_AND_component(inputs_id, inputs_pos, WORD_SIZE)
        T.append(ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))]))

    # S[i] ^= T[(i+1)%5] for i in range(5)
    for i in range(WORD_NUM):
        inputs_id, inputs_pos = get_inputs_parameter([state[i], T[(i + 1) % WORD_NUM]])
        cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[i] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    # S[1] ^= S[0]
    inputs_id, inputs_pos = get_inputs_parameter([state[1], state[0]])
    cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
    state[1] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    # S[3] ^= S[2]
    inputs_id, inputs_pos = get_inputs_parameter([state[3], state[2]])
    cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
    state[3] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    # S[0] ^= S[4]
    inputs_id, inputs_pos = get_inputs_parameter([state[0], state[4]])
    cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
    state[0] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    # S[2] = ~S[2]
    cipher.add_NOT_component(state[2].id, state[2].input_bit_positions, WORD_SIZE)
    state[2] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    inputs = []
    for i in range(WORD_NUM):
        inputs.append(state[i])
    inputs_id, inputs_pos = get_inputs_parameter(inputs)

    # linear layer
    # S[i] ^= rotr(S[i], rot0) ^ rotr(S[i], rot1)
    for i in range(WORD_NUM):
        cipher.add_rotate_component(state[i].id, state[i].input_bit_positions, WORD_SIZE, LINEAR_LAYER_ROT[i][0])
        s1 = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])
        cipher.add_rotate_component(state[i].id, state[i].input_bit_positions, WORD_SIZE, LINEAR_LAYER_ROT[i][1])
        s2 = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])
        inputs_id, inputs_pos = get_inputs_parameter([state[i], s1, s2])
        cipher.add_XOR_component(inputs_id, inputs_pos, WORD_SIZE)
        state[i] = ComponentState([cipher.get_current_component_id()], [list(range(WORD_SIZE))])

    return state

## End of code copied from ascon_base.sage ##

IV_ASCON_128 = 0x80400c0600000000
ASCON_A = 12
ASCON_B = 6

def create_ascon_instance(plaintext_block_size, ad_block_size) -> Cipher:
    plaintext_size = 64 * plaintext_block_size
    ad_size = 64 * ad_block_size
    ciphertext_size = plaintext_size + 128

    if plaintext_block_size==0:
        plaintext_size=8

    if ad_block_size==0:
        ad_size=8
    
    ascon = Cipher("ASCON-128", "AEAD",
                   ["plaintext", "key", "nonce", "ad"],
                   [plaintext_size, 128, 128, ad_size],
                   ciphertext_size)

    ascon.add_round()

    ## Init
    nonce = ComponentState(["nonce"], [list(range(128))])
    key = ComponentState(["key"], [list(range(128))])

    ascon.add_constant_component(64, IV_ASCON_128)
    iv = ComponentState([ascon.get_current_component_id()], [list(range(64))])

    ## State = IV || K || N
    ids, pos = get_inputs_parameter([iv, key, nonce])
    ascon.add_concatenate_component(ids, pos, 320)
    state = ComponentState([ascon.get_current_component_id()], [list(range(320))])

    ## State = p_a(State) ^ (0* || K)
    tmp = ASCON_WRAPPER(ascon, state, ASCON_A)
    ascon.add_constant_component(192, 0)
    zeros = ComponentState([ascon.get_current_component_id()], [list(range(192))])

    ids, pos = get_inputs_parameter([zeros, key])
    ascon.add_concatenate_component(ids, pos, 320)
    padded_key = ComponentState([ascon.get_current_component_id()], [list(range(320))])

    ids, pos = get_inputs_parameter([tmp, padded_key])
    ascon.add_XOR_component(ids, pos, 320)
    state = ComponentState([ascon.get_current_component_id()], [list(range(320))])

    ascon.add_constant_component(64, 1 << 63)
    onezero = ComponentState([ascon.get_current_component_id()], [list(range(64))])

    ## Process AD
    AD = []
    if (ad_block_size > 0):
        for i in range(0, ad_size, 64):
            chunk = ComponentState(["ad"], [list(range(i, i+64))])
            AD.append(chunk)

        AD.append(onezero) ## see spec

        for i in range(ad_block_size+1):
            #input to ascon wrapper: ((Sr ⊕ Ai) || Sc
            s64 = ComponentState(state.id, [list(range(64))])
            sc = ComponentState(state.id, [list(range(64,320))])

            ids, pos = get_inputs_parameter([s64, AD[i]])
            ascon.add_XOR_component(ids, pos, 64)
            s64_xor_ad = ComponentState([ascon.get_current_component_id()], [list(range(64))])

            ids, pos = get_inputs_parameter([s64_xor_ad, sc])
            ascon.add_concatenate_component(ids, pos, 320)
            ascon_input = ComponentState([ascon.get_current_component_id()], [list(range(320))])

            state = ASCON_WRAPPER(ascon, ascon_input, ASCON_B)

    ## State = State ^ (0* || 1)
    ascon.add_constant_component(320, 1)
    tmp = ComponentState([ascon.get_current_component_id()], [list(range(320))])

    ids, pos = get_inputs_parameter([state, tmp])
    ascon.add_XOR_component(ids, pos, 320)
    state = ComponentState([ascon.get_current_component_id()], [list(range(320))])

    ## Processing Plaintext
    PT = []
    CT = []
    if (plaintext_block_size > 0):
        for i in range(0, plaintext_size, 64):
            chunk = ComponentState(["plaintext"], [list(range(i, i+64))])
            PT.append(chunk)

        PT.append(onezero) ## see spec

        for i in range(plaintext_block_size):
            # Sr ← Sr ⊕ Pi ; Ci ← Sr
            s64 = ComponentState(state.id, [list(range(64))])

            ids, pos = get_inputs_parameter([s64, PT[i]])
            ascon.add_XOR_component(ids, pos, 64)
            s64 = ComponentState([ascon.get_current_component_id()], [list(range(64))])
            CT.append(s64)

            sc = ComponentState(state.id, [list(range(64, 320))])

            ## Reconstruct state / Make changes visible
            ids, pos = get_inputs_parameter([s64, sc])
            ascon.add_concatenate_component(ids, pos, 320)
            state = ComponentState([ascon.get_current_component_id()], [list(range(320))])
            
            # S ← ASCON_WRAPPER(S), const=B
            state = ASCON_WRAPPER(ascon, state, ASCON_B)

        ## Last plaintext block, for us, is simply the padding block.
        ## It will not be added to the ciphertext blocks, but still needs to be processed
        ## S_64 = S_64 ^ PT[-1] (S_64 = S[:64] the first 64 bits of the state)
        state_64 = ComponentState(state.id, [list(range(64))])

        ids, pos = get_inputs_parameter([state_64, PT[-1]])
        ascon.add_XOR_component(ids, pos, 64)
        state_64 = ComponentState([ascon.get_current_component_id()], [list(range(64))])

        ## Incorporate state_64 into state
        state_remaining = ComponentState(state.id, [list(range(64, 320))])
        ids, pos = get_inputs_parameter([state_64, state_remaining])
        ascon.add_concatenate_component(ids, pos, 320)
        state = ComponentState([ascon.get_current_component_id()], [list(range(320))])

    # end if

    ## Wrapping Up
    ## State = p_a(State ^ (0_64 || K || 0_128))
    ascon.add_constant_component(64, 0)
    zeros_64 = ComponentState([ascon.get_current_component_id()], [list(range(64))])
    ascon.add_constant_component(128, 0)
    zeros_128 = ComponentState([ascon.get_current_component_id()], [list(range(128))])

    ids, pos = get_inputs_parameter([zeros_64, key, zeros_128])
    ascon.add_concatenate_component(ids, pos, 320)
    padded_key = ComponentState([ascon.get_current_component_id()], [list(range(320))])

    ids, pos = get_inputs_parameter([state, padded_key])
    ascon.add_XOR_component(ids, pos, 320)
    state = ComponentState([ascon.get_current_component_id()], [list(range(320))])

    state = ASCON_WRAPPER(ascon, state, ASCON_A)

    ## tag = (Last 128 bits of State) ^ (Key)
    state_last_128 = ComponentState(state.id, [list(range(192, 320))])
    ids, pos = get_inputs_parameter([state_last_128, key])

    ascon.add_XOR_component(ids, pos, 128)
    tag = ComponentState([ascon.get_current_component_id()], [list(range(128))])

    ids, pos = get_inputs_parameter(CT +  [tag])
    ascon.add_cipher_output_component(ids, pos, ciphertext_size)

    return ascon

def test3():
    ### Evaluation stuff
    print("1 plaintext, 3 AD")
    print("Expected: 0x74A6A39D0A5129583F067A14D9DFFE298CAFBD5D9B084675")
    asc = create_ascon_instance(1,3)
    print("Non-reversed try (should be this one)")

    key   = 0x0001020304050607_08090A0B0C0D0E0F
    nonce = 0x0001020304050607_08090A0B0C0D0E0F

    plaintext = 0x00010203_04050607
    ad        = 0x00010203_04050607_08090A0B_0C0D0E0F_10111213_14151617

    print(hex(asc.evaluate([plaintext,key,nonce,ad])))

def test2():
    ### Evaluation stuff
    print("1 plaintext, 2 AD")
    print("Expected: 0x1EE34125FDBA1744263AC941C6EDEFB49505018DE9DAC9B3")
    asc = create_ascon_instance(1,2)
    print("Non-reversed try (should be this one)")

    key   = 0x0001020304050607_08090A0B0C0D0E0F
    nonce = 0x0001020304050607_08090A0B0C0D0E0F

    plaintext = 0x00010203_04050607
    ad        = 0x00010203_04050607_08090A0B_0C0D0E0F

    print(hex(asc.evaluate([plaintext,key,nonce,ad])))

def test1():
    ### Evaluation stuff
    print("1 plaintext, 1 AD") # 
    print("Expected: 0x69ffee6f5505a489e897e5f141b2e4a2dad326085a79408a")
    asc = create_ascon_instance(1,1)
    print("Non-reversed try (should be this one)")

    key   = 0x0001020304050607_08090A0B0C0D0E0F
    nonce = 0x0001020304050607_08090A0B0C0D0E0F

    plaintext = 0x00010203_04050607
    ad        = 0x00010203_04050607

    print(hex(asc.evaluate([plaintext,key,nonce,ad])))

    print("Reversed try")

    key   = 0x00102030_40506070_8090a0b0_c0d0e0f0
    nonce = 0x00102030_40506070_8090a0b0_c0d0e0f0

    plaintext = 0x00102030_40506070
    ad        = 0x00102030_40506070

    print(hex(asc.evaluate([plaintext,key,nonce,ad])))

def test0():
    ### Evaluation stuff
    print("1 plaintext, 0 AD")
    print("Expected: 0xBC820DBDF7A4631C 01A8807A44254B42AC6BB490DA1E000A")
    asc = create_ascon_instance(1,0)
    print("Non-reversed try (should be this one)")

    key   = 0x0001020304050607_08090A0B0C0D0E0F
    nonce = 0x0001020304050607_08090A0B0C0D0E0F

    plaintext = 0x00010203_04050607
    ad        = 0x0

    print(hex(asc.evaluate([plaintext,key,nonce,ad])))

    print("Reversed try")

    key   = 0x00102030_40506070_8090a0b0_c0d0e0f0
    nonce = 0x00102030_40506070_8090a0b0_c0d0e0f0

    plaintext = 0x00102030_40506070
    ad        = 0x0

    print(hex(asc.evaluate([plaintext,key,nonce,ad])))

#test0()
#test1()