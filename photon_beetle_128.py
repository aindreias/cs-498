from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import get_inputs_parameter
from claasp.ciphers.permutations.photon_permutation import IRREDUCIBLE_POLYNOMIAL, M, IC, PARAMETERS_CONFIGURATION_LIST, RC, S_BOX
from copy import deepcopy

## state is 256 bits when called from here
## Modified code (original is implemented in CLAASP as a Permutation)
def PHOTON_256_WRAPPER(cipher: Cipher, input: ComponentState):
    cell_bits = 4
    d = 8
    t = 256
    state_bit_size = 256
    number_of_rounds = 12

    cipher.add_round_output_component(input.id, input.input_bit_positions, 256)

    # state initialization
    state =[] # [ [0 for _ in range(d)] for _ in range(d)]
    for i in range(d * d):
        state.append(ComponentState(input.id, [[k + i * cell_bits for k in range(cell_bits)]]))

    # For whatever reason, the PHOTON permutation just ?? switches 0xab -> 0xba
    #for (i = 0; i < D * D; i++)
	#{
	#	state[i / D][i % D] = (State_in[i / 2] >> (4 * (i & 1))) & 0xf;
	#}

    # round constant setup
    components_rc = []
    for i in range(len(RC)):
        cipher.add_constant_component(cell_bits, RC[i])
        components_rc.append(ComponentState([cipher.get_current_component_id()], [list(range(cell_bits))]))
    components_ic = []
    for i in range(len(IC)):
        cipher.add_constant_component(cell_bits, IC[i])
        components_ic.append(ComponentState([cipher.get_current_component_id()], [list(range(cell_bits))]))

    for round_number in range(number_of_rounds):
        state = round_function(cipher, state, components_rc[round_number], components_ic)

    ## Reconstruct all the small state[] elems into a 256-bit state
    state_id, state_pos = get_inputs_parameter(state[i] for i in range(d*d))
    cipher.add_concatenate_component(state_id, state_pos, 256)
    reconstructed_state = ComponentState([cipher.get_current_component_id()], [list(range(256))])

    cipher.add_round()

    return reconstructed_state

def round_function(cipher, state, component_rc, components_ic, d=8, cell_bits=4):
    # AddConstant
    # state[i,0] = state[i,0] xor RC[r] xor IC[i] for i in range(d)
    for i in range(d):
        inputs_id, inputs_pos = get_inputs_parameter([state[i * d], component_rc, components_ic[i]])
        cipher.add_XOR_component(inputs_id, inputs_pos, cell_bits)
        state[i * d] = ComponentState([cipher.get_current_component_id()], [list(range(cell_bits))])

    # SubCells
    # state[i,j] = s_box(state[i, j])
    for i in range(d * d):
        cipher.add_SBOX_component(state[i].id, state[i].input_bit_positions, cell_bits, S_BOX)
        state[i] = ComponentState([cipher.get_current_component_id()], [list(range(cell_bits))])

    # ShiftRows
    # state_new[i,j] = state[i, (j+i)%8) for i,j in range(8)
    state_new = []
    for i in range(d):
        for j in range(d):
            state_new.append(state[i * d + ((j + i) % 8)])
    state = deepcopy(state_new)

    # MixColumnSerials
    # state = M x state
    for i in range(d):
        inputs_id, inputs_pos = get_inputs_parameter([state[i + j * d] for j in range(d)])
        cipher.add_mix_column_component(inputs_id, inputs_pos, cell_bits * d,
                                          [M, IRREDUCIBLE_POLYNOMIAL, cell_bits])
        for j in range(d):
            state[i + j * d] = ComponentState([cipher.get_current_component_id()],
                                                       [[k + j * cell_bits for k in range(cell_bits)]])

    return state

def shuffle_s(cipher, s: ComponentState):
    s1 = ComponentState(s.id, [list(range(64))])
    s2 = ComponentState(s.id, [list(range(64, 128))])

    ## S1 >>> 1
    cipher.add_rotate_component(s1.id, s1.input_bit_positions, 64, 1)
    s1_rot = ComponentState([cipher.get_current_component_id()], [list(range(64))])

    ## Result = S2 || (S1 >>> 1)
    ids, pos = get_inputs_parameter([s2, s1_rot])
    cipher.add_concatenate_component(ids, pos, 128)
    
    return ComponentState([cipher.get_current_component_id()], [list(range(128))])

def rho_pb(cipher, s, u):
    shfl_s = shuffle_s(cipher, s)

    # V = Shuffle(S) ^ U
    ids, pos = get_inputs_parameter([shfl_s, u])
    cipher.add_XOR_component(ids, pos, 128)
    v = ComponentState([cipher.get_current_component_id()], [list(range(128))])

    # S = S ^ U
    ids, pos = get_inputs_parameter([s, u])
    cipher.add_XOR_component(ids, pos, 128)
    s = ComponentState([cipher.get_current_component_id()], [list(range(128))])

    return s,v
    
def tag_128(cipher, t0):
    t = PHOTON_256_WRAPPER(cipher, t0)
    
    tag = ComponentState(t.id, [list(range(128))])

    return tag

def hash_128(cipher: Cipher, iv: ComponentState, d: ComponentState, block_size, c0:ComponentState):
    D = []
    for i in range(0, 128*block_size):
        chunk = ComponentState(d.id, [list(range(i, i+128))])
        D.append(chunk)

    for i in range(block_size):
        # Y||Z = PHOTON(IV)
        yz = PHOTON_256_WRAPPER(cipher, iv)

        y = ComponentState(yz.id, [list(range(128))])
        z = ComponentState(yz.id, [list(range(128, 256))])

        # W = Y ^ D[i]
        ids, pos = get_inputs_parameter([y, D[i]])
        cipher.add_XOR_component(ids, pos, 128)
        w = ComponentState([cipher.get_current_component_id()], [list(range(128))])

        # IV = W || Z
        ids, pos = get_inputs_parameter([w, z])
        cipher.add_concatenate_component(ids, pos, 256)
        iv = ComponentState([cipher.get_current_component_id()], [list(range(256))])
    ## end for

    # IV = IV ^ c0
    ids, pos = get_inputs_parameter([iv, c0])
    cipher.add_XOR_component(ids, pos, 256)
    iv = ComponentState([cipher.get_current_component_id()], [list(range(256))])

    return iv

def create_photon_beetle_instance(plaintext_block_size, ad_block_size) -> Cipher:
    plaintext_size = 128 * plaintext_block_size
    ad_size = 128 * ad_block_size
    ciphertext_size = plaintext_size + 128

    if plaintext_block_size==0:
        plaintext_size=8

    if ad_block_size==0:
        ad_size=8

    photon_beetle = Cipher("PHOTON-Beetle-AEAD[128]", "AEAD",
                           ["plaintext", "key", "nonce", "ad"],
                           [plaintext_size, 128, 128, ad_size],
                           ciphertext_size)

    photon_beetle.add_round()

    key   = ComponentState(["key"],   [list(range(128))])
    nonce = ComponentState(["nonce"], [list(range(128))])

    # IV = N || K
    ids, pos = get_inputs_parameter([nonce, key])
    photon_beetle.add_concatenate_component(ids, pos, 256)
    iv = ComponentState([photon_beetle.get_current_component_id()], [list(range(256))])

    ## If no msg & no ad => shortcut
    if (plaintext_block_size == 0 and ad_block_size == 0):
        # T = Tag_128(IV ^ 1)

        ## /!\ 0x02 is not a mistake /!\
        ## PHOTON team does as follows: state ^= 0x20;
        ##     (to XOR state to a constant they do state ^= (const << 5))
        ## However, they have a different word order; so 0x02 here is
        ##     what gets the good test vectors for empty AD, empty MSG
        photon_beetle.add_constant_component(256, (0x02))
        one = ComponentState([photon_beetle.get_current_component_id()], [list(range(256))])

        ids, pos = get_inputs_parameter([iv, one])
        photon_beetle.add_XOR_component(ids, pos, 256)
        tmp = ComponentState([photon_beetle.get_current_component_id()], [list(range(256))])

        tag = tag_128(photon_beetle, tmp)

        photon_beetle.add_cipher_output_component(tag.id, tag.input_bit_positions, 128)

        print("shortcut done")

        return photon_beetle

    ## Compute c0, c1
    tmp0 = -1; tmp1 = -1;

    ## /!\ not mistakes /!\ see above
    ## 1 << 5 = 0x20 ---> we use 0x02
    ## 2 << 5 = 0x40 ---> we use 0x04
    ## 3 << 5 = 0x60 ---> we use 0x06
    ## 4 << 5 = 0x80 ---> we use 0x08
    ## 5 << 5 = 0xa0 ---> we use 0x0a
    ## 6 << 5 = 0xc0 ---> we use 0x0c
    if (plaintext_block_size != 0):
        tmp0 = 0x02 if (128 | (128*ad_block_size)) else 0x04
    else:
        tmp0 = 0x06 if (128 | (128*ad_block_size)) else 0x08

    if (ad_block_size != 0):
        tmp1 = 0x02 if (128 | (128*plaintext_block_size)) else 0x04
    else:
        tmp1 = 0x0a if (128 | (128*plaintext_block_size)) else 0x0c

    photon_beetle.add_constant_component(256, tmp0)
    c0 = ComponentState([photon_beetle.get_current_component_id()], [list(range(256))])

    photon_beetle.add_constant_component(256, tmp1)
    c1 = ComponentState([photon_beetle.get_current_component_id()], [list(range(256))])

    # AD Processing
    if(ad_block_size != 0):
        associated_data = ComponentState(["ad"], [list(range(ad_size))])
        iv = hash_128(photon_beetle, iv, associated_data, ad_block_size, c0)

    # PT Processing
    M = []; CT = []
    if(plaintext_block_size != 0):
        for i in range(0, plaintext_size, 128):
            chunk = ComponentState(["plaintext"], [list(range(i, i+128))])
            M.append(chunk)

        for i in range(plaintext_block_size):
            ## Y || Z = PHOTON(IV)
            yz = PHOTON_256_WRAPPER(photon_beetle, iv)

            y = ComponentState(yz.id, [list(range(128))])
            z = ComponentState(yz.id, [list(range(128,256))])

            ## (W,Ci) = RHO(Y, M[i])
            w, ci = rho_pb(photon_beetle, y, M[i])
            CT.append(ci)

            # IV = W || Z
            ids, pos = get_inputs_parameter([w, z])
            photon_beetle.add_concatenate_component(ids, pos, 256)
            iv = ComponentState([photon_beetle.get_current_component_id()], [list(range(256))])

        # IV = IV ^ c1
        ids, pos = get_inputs_parameter([iv, c1])
        photon_beetle.add_XOR_component(ids, pos, 256)
        iv = ComponentState([photon_beetle.get_current_component_id()], [list(range(256))])

    # Tag 
    tag = tag_128(photon_beetle, iv)

    ids, pos = get_inputs_parameter(CT + [tag])
    photon_beetle.add_cipher_output_component(ids, pos, ciphertext_size)

    return photon_beetle
