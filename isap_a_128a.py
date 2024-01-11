from claasp.utils.utils import get_inputs_parameter
from claasp.DTOs.component_state import ComponentState
from claasp.cipher import Cipher

ENC=0; MAC=1;
RH=64; RB=1; SH=12; SB=1; SE=6; SK=12

# 72 bits (padded to 192 bits)
IV_A  = 0x018040010C01060C00 << 120
IV_KA = 0X028040010C01060C00 << 120
IV_KE = 0X038040010C01060C00 << 120

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

        # round parameter
        ci = 0xf0 - r * 0x10 + r * 0x1

        # round function
        state = round_function(cipher, state, ci)

        # round output
        inputs = []
        for i in range(WORD_NUM):
            inputs.append(state[i])
        ids, pos = get_inputs_parameter(inputs)

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

## key has  128 bits
## y   has  128 bits
## ivs have 192 bits
def isap_round_key(cipher: Cipher, key, flag, y:ComponentState, const_iv_a, const_iv_ka, const_iv_ke):
    z = 0; iv = const_iv_ke
    ## Init
    if (flag == ENC):
        # IV = IV_KE
        iv = const_iv_ke

        # z = n-k = 320-128
        z = 192
    else:
        # IV = IV_KA
        iv = const_iv_ka

        # z = k = 128
        z = 128

    y_array = []
    for i in range(128):
        yi = ComponentState(y.id, [[i]])
        y_array.append(yi)

    ids, pos = get_inputs_parameter([key, iv])
    cipher.add_concatenate_component(ids, pos, 320)

    # s = k || iv
    state = ComponentState([cipher.get_current_component_id()], [list(range(320))])

    # s = pk(s)
    state = ASCON_WRAPPER(cipher, state, SK)

    ## Absorb
    for i in range(127):
        yi = y_array[i]

        srb = ComponentState(state.id, [[0]])
        scb = ComponentState(state.id, [list(range(1, 320))])

        # s = pb((Srb ^ yi) || Scb)
        cipher.add_XOR_component(srb.id + yi.id, srb.input_bit_positions + yi.input_bit_positions, 1)
        tmp = ComponentState([cipher.get_current_component_id()], [[0]])

        cipher.add_concatenate_component(tmp.id+scb.id, tmp.input_bit_positions+scb.input_bit_positions,320)
        tmp = ComponentState([cipher.get_current_component_id()], [list(range(320))])

        state = ASCON_WRAPPER(cipher, tmp, SB)

    # s = pk((Srb ^ yi) || Scb)
    yi = y_array[127]

    srb = ComponentState(state.id, [[0]])
    scb = ComponentState(state.id, [list(range(1, 320))])

    cipher.add_XOR_component(srb.id + yi.id, srb.input_bit_positions + yi.input_bit_positions, 1)
    tmp = ComponentState([cipher.get_current_component_id()], [[0]])

    cipher.add_concatenate_component(tmp.id+scb.id, tmp.input_bit_positions+scb.input_bit_positions,320)
    tmp = ComponentState([cipher.get_current_component_id()], [list(range(320))])

    state = ASCON_WRAPPER(cipher, tmp, SK)

    ## Squeeze: round_key = first z bits of the state
    rk = ComponentState(state.id, [list(range(z))])

    return rk

## key   has 128 bits [Component]
## nonce has 128 bits [Component]
## CT    has chunks of 64 bits [list]
## AD    has chunks of 64 bits [list]
def isap_mac(cipher: Cipher, key: ComponentState, nonce: ComponentState,
             CT:list, AD:list, const_iv_a, const_iv_ka, const_iv_ke):
    ## ci = 64-bit blocks of C
    # (already have ct so all good)

    ## /!\ AD, CT lists are appended with (1 000 ... 000) (64bits)
    ## see specification
    cipher.add_constant_component(64, 1 << 63)
    onezero = ComponentState([cipher.get_current_component_id()], [list(range(64))])

    AD.append(onezero)
    CT.append(onezero)

    # s = n || iv_a
    ids, pos = get_inputs_parameter([nonce, const_iv_a])
    cipher.add_concatenate_component(ids, pos, 320)
    state = ComponentState([cipher.get_current_component_id()], [list(range(320))])

    # s = ph(s)
    state = ASCON_WRAPPER(cipher, state, SH)

    ## Absorb AD
    for i in range(len(AD)):
        # S = Ph((S64 ^ AD[i]) || S_last)
        s_64   = ComponentState(state.id, [list(range(64))])
        s_last = ComponentState(state.id, [list(range(64, 320))])

        ids, pos = get_inputs_parameter([s_64, AD[i]])
        cipher.add_XOR_component(ids, pos, 64)
        s64_xor_ad = ComponentState([cipher.get_current_component_id()], [list(range(64))])

        ids, pos = get_inputs_parameter([s64_xor_ad, s_last])
        cipher.add_concatenate_component(ids, pos, 320)
        ascon_input = ComponentState([cipher.get_current_component_id()], [list(range(320))])

        state = ASCON_WRAPPER(cipher, ascon_input, SH)

    #s = s ^ (0 319 times) || 1
    cipher.add_constant_component(320, 1)
    mask = ComponentState([cipher.get_current_component_id()], [list(range(320))])

    ids, pos = get_inputs_parameter([state, mask])
    cipher.add_XOR_component(ids, pos, 320)
    state = ComponentState([cipher.get_current_component_id()], [list(range(320))])

    ## Absorb CT
    for i in range(len(CT)):
        # s = Ph((S64 ^ CT[i]) || S_last)
        s_64   = ComponentState(state.id, [list(range(64))])
        s_last = ComponentState(state.id, [list(range(64, 320))])

        ids, pos = get_inputs_parameter([s_64, CT[i]])
        cipher.add_XOR_component(ids, pos, 64)
        s64_xor_ct = ComponentState([cipher.get_current_component_id()], [list(range(64))])

        ids, pos = get_inputs_parameter([s64_xor_ct, s_last])
        cipher.add_concatenate_component(ids, pos, 320)
        ascon_input = ComponentState([cipher.get_current_component_id()], [list(range(320))])

        state = ASCON_WRAPPER(cipher, ascon_input, SH)

    ## KA = ISAP_RK(K, MAC, first 128 bits of S)
    s_128 = ComponentState(state.id, [list(range(128))])
    ka = isap_round_key(cipher, key, MAC, s_128, const_iv_a, const_iv_ka, const_iv_ke)

    # s = ph(ka || last (n-k=320-128=192) bits of state)
    s_192 = ComponentState(state.id, [list(range(128, 320))])

    ids, pos = get_inputs_parameter([ka, s_192])
    cipher.add_concatenate_component(ids, pos, 320)
    tmp = ComponentState([cipher.get_current_component_id()], [list(range(320))])

    state = ASCON_WRAPPER(cipher, tmp, SH)

    # tag = first (k=128) bits of s 
    tag = ComponentState(state.id, [list(range(128))])

    cipher.add_round_output_component(state.id, state.input_bit_positions, 320)
    cipher.add_round()

    ## undoing
    CT.remove(onezero)
    AD.remove(onezero)

    return tag

## key   has 128 bits [Component]
## nonce has 128 bits [Component]
## pt    has blocks of 64 bits each;
def isap_enc(cipher: Cipher, key: ComponentState, nonce:ComponentState,
             PT: list, const_iv_a, const_iv_ka, const_iv_ke):
    
    ## KE = ISAP_RK(K, ENC, Nonce)
    ke = isap_round_key(cipher, key, ENC, nonce, const_iv_a, const_iv_ka, const_iv_ke)

    # s = KE || Nonce
    ids, pos = get_inputs_parameter([ke, nonce])
    cipher.add_concatenate_component(ids, pos, 320)

    state = ComponentState([cipher.get_current_component_id()], [list(range(320))])

    CT = []
    for i in range(len(PT)):
        # State  = Pe(State)
        state = ASCON_WRAPPER(cipher, state, SE)

        # Ci = S64 ^ PT[i]
        s_64 = ComponentState(state.id, [list(range(64))])
        ids, pos = get_inputs_parameter([s_64, PT[i]])
        cipher.add_XOR_component(ids, pos, 64)
        ci = ComponentState([cipher.get_current_component_id()], [list(range(64))])

        CT.append(ci)

    cipher.add_round_output_component(state.id, state.input_bit_positions, 320)
    cipher.add_round()

    return CT

def create_isap_instance(plaintext_block_size, ad_block_size) -> Cipher:
    plaintext_size = 64 * plaintext_block_size
    ad_size = 64 * ad_block_size
    ciphertext_size = plaintext_size + 128

    if plaintext_block_size==0:
        plaintext_size=8

    if ad_block_size==0:
        ad_size=8

    isap = Cipher("ISAP-A-128A", "AEAD",
                  ["plaintext", "key", "nonce", "ad"],
                  [plaintext_size, 128, 128, ad_size],
                  ciphertext_size)

    isap.add_round()

    key   = ComponentState(["key"],   [list(range(128))])
    nonce = ComponentState(["nonce"], [list(range(128))])

    # IV_A = (IV_A) + 120 bits of 0-padding
    isap.add_constant_component(192, IV_A)
    const_iv_a = ComponentState([isap.get_current_component_id()], [list(range(192))])

    # IV_KA (same idea as above)
    isap.add_constant_component(192, IV_KA)
    const_iv_ka = ComponentState([isap.get_current_component_id()], [list(range(192))])

    # IV_KE (same idea as above)
    isap.add_constant_component(192, IV_KE)
    const_iv_ke = ComponentState([isap.get_current_component_id()], [list(range(192))])

    ## Get PT chunks
    PT = []
    if (plaintext_block_size != 0):
        for i in range(0, plaintext_size, 64):
            chunk = ComponentState(["plaintext"], [list(range(i, i+64))])
            PT.append(chunk)

    ## Get AD chunks
    AD = []
    if (ad_block_size != 0):
        for i in range(0, ad_size, 64):
            chunk = ComponentState(["ad"], [list(range(i, i+64))])
            AD.append(chunk)

    CT = isap_enc(isap, key, nonce, PT, const_iv_a, const_iv_ka, const_iv_ke)

    tag = isap_mac(isap, key, nonce, CT, AD, const_iv_a, const_iv_ka, const_iv_ke)

    ## Mark outputs
    ids, pos = get_inputs_parameter(CT +  [tag])
    isap.add_cipher_output_component(ids, pos, ciphertext_size)

    return isap

def test0():
    print("1 PT, 0 AD")
    print("Expected: 0x2CDE28DBBBD9131ED3F44B4FB43055D5AC109F83F530D165")
    isap = create_isap_instance(1, 0)
    
    print("Non-reversed try (should be this one)")

    key   = 0x0001020304050607_08090A0B0C0D0E0F
    nonce = 0x0001020304050607_08090A0B0C0D0E0F

    plaintext = 0x00010203_04050607
    ad        = 0x0

    print(hex(isap.evaluate([plaintext,key,nonce,ad])))

    print("Reversed try")

    key   = 0x00102030_40506070_8090a0b0_c0d0e0f0
    nonce = 0x00102030_40506070_8090a0b0_c0d0e0f0

    plaintext = 0x00102030_40506070
    ad        = 0x0

    print(hex(isap.evaluate([plaintext,key,nonce,ad])))

def test1():
    print("1 PT, 1 AD")
    print("Expected: 0x2CDE28DBBBD9131E4270DFFF9B0C36C0824E86D98DAED276")
    isap = create_isap_instance(1, 1)
    
    print("Non-reversed try (should be this one)")

    key   = 0x0001020304050607_08090A0B0C0D0E0F
    nonce = 0x0001020304050607_08090A0B0C0D0E0F

    plaintext = 0x00010203_04050607
    ad        = 0x00010203_04050607

    print(hex(isap.evaluate([plaintext,key,nonce,ad])))

    print("Reversed try")

    key   = 0x00102030_40506070_8090a0b0_c0d0e0f0
    nonce = 0x00102030_40506070_8090a0b0_c0d0e0f0

    plaintext = 0x00102030_40506070
    ad        = 0x00102030_40506070

    print(hex(isap.evaluate([plaintext,key,nonce,ad])))

#test0()
#test1()