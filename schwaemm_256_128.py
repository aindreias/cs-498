from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.ciphers.permutations.sparkle_permutation import SparklePermutation
from claasp.utils.utils import get_inputs_parameter
from copy import deepcopy

from sparkle_utils import claasp_sparkle_384

## SCHWAEMM 256-128

# ALZETTE OK: checked with CRAX
def alzette_sparkle(cipher: Cipher, x: ComponentState, y:ComponentState, const_alzette):
    # (x) += ROT((y), 31), (y) ^= ROT((x), 24)
    # (x) ^= (c)
    cipher.add_rotate_component(y.id, y.input_bit_positions, 32, 31)
    tmp_y = ComponentState([cipher.get_current_component_id()], [list(range(32))])
    cipher.add_MODADD_component(x.id + tmp_y.id, x.input_bit_positions + tmp_y.input_bit_positions, 32)
    x = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    cipher.add_rotate_component(x.id, x.input_bit_positions, 32, 24)
    tmp_x = ComponentState([cipher.get_current_component_id()], [list(range(32))])
    cipher.add_XOR_component(y.id + tmp_x.id, y.input_bit_positions + tmp_x.input_bit_positions, 32)
    y = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    cipher.add_XOR_component(x.id + const_alzette.id, x.input_bit_positions + const_alzette.input_bit_positions, 32)
    x = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    #  (x) += ROT((y), 17), (y) ^= ROT((x), 17)
    #  (x) ^= (c), 
    cipher.add_rotate_component(y.id, y.input_bit_positions, 32, 17)
    tmp_y = ComponentState([cipher.get_current_component_id()], [list(range(32))])
    cipher.add_MODADD_component(x.id + tmp_y.id, x.input_bit_positions + tmp_y.input_bit_positions, 32)
    x = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    cipher.add_rotate_component(x.id, x.input_bit_positions, 32, 17)
    tmp_x = ComponentState([cipher.get_current_component_id()], [list(range(32))])
    cipher.add_XOR_component(y.id + tmp_x.id, y.input_bit_positions + tmp_x.input_bit_positions, 32)
    y = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    cipher.add_XOR_component(x.id + const_alzette.id, x.input_bit_positions + const_alzette.input_bit_positions, 32)
    x = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    #  (x) += (y),          (y) ^= ROT((x), 31), 
    #  (x) ^= (c),       
    cipher.add_MODADD_component(x.id + y.id, x.input_bit_positions + y.input_bit_positions, 32)
    x = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    cipher.add_rotate_component(x.id, x.input_bit_positions, 32, 31)
    tmp_x = ComponentState([cipher.get_current_component_id()], [list(range(32))])
    cipher.add_XOR_component(y.id + tmp_x.id, y.input_bit_positions + tmp_x.input_bit_positions, 32)
    y = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    cipher.add_XOR_component(x.id + const_alzette.id, x.input_bit_positions + const_alzette.input_bit_positions, 32)
    x = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    #  (x) += ROT((y), 24), (y) ^= ROT((x), 16)
    #  (x) ^= (c)    
    cipher.add_rotate_component(y.id, y.input_bit_positions, 32, 24)
    tmp_y = ComponentState([cipher.get_current_component_id()], [list(range(32))])
    cipher.add_MODADD_component(x.id + tmp_y.id, x.input_bit_positions + tmp_y.input_bit_positions, 32)
    x = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    cipher.add_rotate_component(x.id, x.input_bit_positions, 32, 16)
    tmp_x = ComponentState([cipher.get_current_component_id()], [list(range(32))])
    cipher.add_XOR_component(y.id + tmp_x.id, y.input_bit_positions + tmp_x.input_bit_positions, 32)
    y = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    cipher.add_XOR_component(x.id + const_alzette.id, x.input_bit_positions + const_alzette.input_bit_positions, 32)
    x = ComponentState([cipher.get_current_component_id()], [list(range(32))])

    return x, y

def w_128_256(cipher, xy):
    cipher.add_concatenate_component(xy.id + xy.id, xy.input_bit_positions + xy.input_bit_positions, 256)

    return ComponentState([cipher.get_current_component_id()], [list(range(256))])

def rho_1(cipher, s: ComponentState, d: ComponentState):
    s1 = ComponentState(s.id, [list(range(128))])
    s2 = ComponentState(s.id, [list(range(128, 256))])

    ## feistel swap
    cipher.add_XOR_component(s1.id + s2.id, s1.input_bit_positions + s2.input_bit_positions, 128)
    tmp = ComponentState([cipher.get_current_component_id()], [list(range(128))])

    cipher.add_concatenate_component(s2.id + tmp.id, s2.input_bit_positions + tmp.input_bit_positions, 256)
    feistel_swap = ComponentState([cipher.get_current_component_id()], [list(range(256))])

    ## result
    cipher.add_XOR_component(feistel_swap.id + d.id, feistel_swap.input_bit_positions + d.input_bit_positions, 256)

    return ComponentState([cipher.get_current_component_id()], [list(range(256))])

def rho_2(cipher, s, d):
    cipher.add_XOR_component(s.id + d.id, s.input_bit_positions + d.input_bit_positions, 256)

    return ComponentState([cipher.get_current_component_id()], [list(range(256))])

def sparkle_384_n(cipher:Cipher, sp_in: ComponentState, n) -> (ComponentState, ComponentState):
    cipher.add_round()

    ## Make the constant components
    tmp = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D]
    const_sparkle = []

    for i in range(8):
        cipher.add_constant_component(32, tmp[i])
        const_sparkle.append(ComponentState([cipher.get_current_component_id()], [list(range(32))]))

    ## Slice the 384-bit input into 6 (x, y) pairs
    x_components = []
    y_components = []

    for i in range(6):
        x_components.append(ComponentState(sp_in.id, [[(i*64 + j     ) for j in range(32)]]))
        y_components.append(ComponentState(sp_in.id, [[(i*64 + j + 32) for j in range(32)]]))

    for s in range(n):
        # y0 ^= c[s%8]
        cipher.add_XOR_component(y_components[0].id + const_sparkle[s%8].id, y_components[0].input_bit_positions + const_sparkle[s%8].input_bit_positions, 32)
        y_components[0] = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        # y1 ^= s mod (2**32)
        cipher.add_constant_component(32, s)
        const_s = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_XOR_component(y_components[1].id + const_s.id, y_components[1].input_bit_positions + const_s.input_bit_positions, 32)
        y_components[1] = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        ## pass (x_i, y_i) to Alzette
        for i in range(6):
            x_i, y_i = alzette_sparkle(cipher, x_components[i], y_components[i], const_sparkle[i])
            x_components[i] = x_i
            y_components[i] = y_i

        ## Linear Layer L6

        ## tx = x0 ^ x1 ^ x2
        ids, pos = get_inputs_parameter(x_components[0:3])
        cipher.add_XOR_component(ids, pos,32)
        tx = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        ## ty = y0 ^ y1 ^ y2
        ids, pos = get_inputs_parameter(y_components[0:3])
        cipher.add_XOR_component(ids, pos,32)
        ty = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        ## tx = (tx ^ (tx << 16)) <<< 16
        ## where (<< = shift, <<< = rotate)
        cipher.add_SHIFT_component(tx.id, tx.input_bit_positions, 32, -16)
        tx_shift = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_XOR_component(tx.id + tx_shift.id, tx.input_bit_positions + tx_shift.input_bit_positions, 32)
        tmp_xor = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_rotate_component(tmp_xor.id, tmp_xor.input_bit_positions, 32, -16)
        tx = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        ## ty = (ty ^ (ty << 16)) <<< 16
        cipher.add_SHIFT_component(ty.id, ty.input_bit_positions, 32, -16)
        ty_shift = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_XOR_component(ty.id + ty_shift.id, ty.input_bit_positions + ty_shift.input_bit_positions, 32)
        tmp_xor = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_rotate_component(tmp_xor.id, tmp_xor.input_bit_positions, 32, -16)
        ty = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        ## (y3, y4, y5) <- (y3 ^ y0 ^ tx, y4 ^ y1 ^ tx, y5 ^ y2 ^ tx)
        cipher.add_XOR_component(y_components[3].id + y_components[0].id + tx.id,
                                y_components[3].input_bit_positions + y_components[0].input_bit_positions + tx.input_bit_positions,
                                32)
        y_components[3] = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_XOR_component(y_components[4].id + y_components[1].id + tx.id,
                                y_components[4].input_bit_positions + y_components[1].input_bit_positions + tx.input_bit_positions,
                                32)
        y_components[4] = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_XOR_component(y_components[5].id + y_components[2].id + tx.id,
                                y_components[5].input_bit_positions + y_components[2].input_bit_positions + tx.input_bit_positions,
                                32)
        y_components[5] = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        ## (x3, x4, x5) <- (x3 ^ x0 ^ ty, x4 ^ x1 ^ ty, x5 ^ x2 ^ ty)
        cipher.add_XOR_component(x_components[3].id + x_components[0].id + ty.id,
                                x_components[3].input_bit_positions + x_components[0].input_bit_positions + ty.input_bit_positions,
                                32)
        x_components[3] = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_XOR_component(x_components[4].id + x_components[1].id + ty.id,
                                x_components[4].input_bit_positions + x_components[1].input_bit_positions + ty.input_bit_positions,
                                32)
        x_components[4] = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        cipher.add_XOR_component(x_components[5].id + x_components[2].id + ty.id,
                                x_components[5].input_bit_positions + x_components[2].input_bit_positions + ty.input_bit_positions,
                                32)
        x_components[5] = ComponentState([cipher.get_current_component_id()], [list(range(32))])

        # (x0, x1, x2, x3, x4, x5) <- (x4, x5, x3, x0, x1, x2)
        # (y0, y1, y2, y3, y4, y5) <- (y4, y5, y3, y0, y1, y2)

        tmp0 = x_components[0]; x_components[0] = x_components[4]
        tmp1 = x_components[1]; x_components[1] = x_components[5]
        tmp2 = x_components[2]; x_components[2] = x_components[3]
        x_components[3] = tmp0
        x_components[4] = tmp1
        x_components[5] = tmp2

        tmp0 = y_components[0]; y_components[0] = y_components[4]
        tmp1 = y_components[1]; y_components[1] = y_components[5]
        tmp2 = y_components[2]; y_components[2] = y_components[3]
        y_components[3] = tmp0
        y_components[4] = tmp1
        y_components[5] = tmp2

    ## end for

    ## Now, we have to assemble into State_left and state_right
    ## State_left gets xi,yi for i = 0, 1, 2, 3
    ## State right gets them for i = 4, 5

    cipher.add_concatenate_component(x_components[0].id + y_components[0].id
                                    + x_components[1].id + y_components[1].id
                                    + x_components[2].id + y_components[2].id
                                    + x_components[3].id + y_components[3].id,
                                    
                                    x_components[0].input_bit_positions + y_components[0].input_bit_positions
                                    + x_components[1].input_bit_positions + y_components[1].input_bit_positions
                                    + x_components[2].input_bit_positions + y_components[2].input_bit_positions
                                    + x_components[3].input_bit_positions + y_components[3].input_bit_positions,
                                    256)

    state_left = ComponentState([cipher.get_current_component_id()], [list(range(256))])

    cipher.add_concatenate_component(x_components[4].id + y_components[4].id
                                    + x_components[5].id + y_components[5].id,
                                    
                                    x_components[4].input_bit_positions + y_components[4].input_bit_positions
                                    + x_components[5].input_bit_positions + y_components[5].input_bit_positions,
                                    128)

    state_right = ComponentState([cipher.get_current_component_id()], [list(range(128))])

    cipher.add_round_output_component(state_left.id+state_right.id, state_left.input_bit_positions+state_right.input_bit_positions, 384)

    return state_left, state_right

## Returns state_left & state_right
def sparkle_384_11(cipher: Cipher, sp_in: ComponentState) -> (ComponentState, ComponentState):
    return sparkle_384_n(cipher, sp_in, 11)

## Returns state_left & state_right
def sparkle_384_7(cipher: Cipher, sp_in: ComponentState) -> (ComponentState, ComponentState):
    return sparkle_384_n(cipher, sp_in, 7)
    
def create_schwaemm_instance(plaintext_block_count, ad_block_count) -> Cipher:
    plaintext_size = 256 * plaintext_block_count
    ad_size = 256 * ad_block_count

    schwaemm = Cipher("SCHWAEMM-256-128", "AEAD", 
                      ["plaintext", "key", "nonce", "ad"],
                      [plaintext_size if plaintext_size !=0 else 8, 128, 256, ad_size if ad_size !=0 else 8],
                      plaintext_size+128)

    schwaemm.add_round()

    ## Init: get the key, nonce blocks + the ad, m block lists
    key = ComponentState(["key"], [list(range(128))])
    const_nonce = ComponentState(["nonce"], [list(range(256))])

    ## Pre-processing AD & M: get them into 256-bit chunks each
    AD = []
    M = []

    for i in range(0, 256*ad_block_count, 256):
        chunk = ComponentState(["ad"], [list(range(i, i+256))])
        AD.append(chunk)

    for i in range(0, 256*plaintext_block_count, 256):
        chunk = ComponentState(["plaintext"], [list(range(i, i+256))])
        M.append(chunk)

    schwaemm.add_constant_component(128, 5 << 24) ## 1 xor (1 << 2), since AD blocks are all full
    const_a = ComponentState([schwaemm.get_current_component_id()], [list(range(128))])

    schwaemm.add_constant_component(128, 7 << 24) ## 3 xor (1 << 2), since M blocks are all full
    const_m = ComponentState([schwaemm.get_current_component_id()], [list(range(128))])

    ## N || K go to sparkle_384_11
    ids, pos = get_inputs_parameter([const_nonce, key])
    schwaemm.add_concatenate_component(ids, pos, 384)
    tmp_nk = ComponentState([schwaemm.get_current_component_id()], [list(range(384))])

    #TODO later:
    # schwaemm.add_round_output_component(tmp_nk.id, tmp_nk.input_bit_positions, 384)

    state_left, state_right = sparkle_384_11(schwaemm, tmp_nk)

    ## Processing the Associated Data

    if(len(AD) > 0):
        for i in range(ad_block_count - 1):
            tmp_rho_1 = rho_1(schwaemm, state_left, AD[i])
            tmp_w_128_256 = w_128_256(schwaemm, state_right)

            ids, pos = get_inputs_parameter([tmp_rho_1, tmp_w_128_256])
            schwaemm.add_XOR_component(ids, pos, 256)
            tmp_xor = ComponentState([schwaemm.get_current_component_id()], [list(range(256))])

            ids, pos = get_inputs_parameter([tmp_xor, state_right])
            schwaemm.add_concatenate_component(ids, pos, 384)
            sparkle_input = ComponentState([schwaemm.get_current_component_id()], [list(range(384))])

            state_left, state_right = sparkle_384_7(schwaemm, sparkle_input)
            schwaemm.add_round()

        tmp_rho_1 = rho_1(schwaemm, state_left, AD[ad_block_count-1])

        ids, pos = get_inputs_parameter([state_right, const_a])
        schwaemm.add_XOR_component(ids, pos, 128)
        sr_xor_ca =  ComponentState([schwaemm.get_current_component_id()], [list(range(128))])
        tmp_w_128_256 = w_128_256(schwaemm, sr_xor_ca)

        ids, pos = get_inputs_parameter([tmp_rho_1, tmp_w_128_256])
        schwaemm.add_XOR_component(ids, pos, 256)
        tmp_xor = ComponentState([schwaemm.get_current_component_id()], [list(range(256))])

        ids, pos = get_inputs_parameter([tmp_xor, sr_xor_ca])
        schwaemm.add_concatenate_component(ids, pos, 384)
        sparkle_input = ComponentState([schwaemm.get_current_component_id()], [list(range(384))])

        state_left, state_right = sparkle_384_11(schwaemm, sparkle_input)
        schwaemm.add_round()

    ## Processing the Plaintext
    CT = []
    if (len(M) > 0):
        for i in range(plaintext_block_count-1):
            CT.append(rho_2(schwaemm, state_left, M[i]))

            tmp_rho_1 = rho_1(schwaemm, state_left, M[i])
            tmp_w_128_256 = w_128_256(state_right)

            ids, pos = get_inputs_parameter([tmp_rho_1, tmp_w_128_256])
            schwaemm.add_XOR_component(ids, pos, 256)
            tmp_xor = ComponentState([schwaemm.get_current_component_id()], [list(range(256))])

            ids, pos = get_inputs_parameter([tmp_xor, state_right])
            schwaemm.add_concatenate_component(ids, pos, 384)
            sparkle_input = ComponentState([schwaemm.get_current_component_id()], [list(range(384))])

            state_left, state_right = sparkle_384_7(schwaemm, sparkle_input)
            schwaemm.add_round()

        CT.append(rho_2(schwaemm, state_left, M[plaintext_block_count-1]))

        ## Preparing input for SPARKLE_384_11
        schwaemm.add_XOR_component(state_right.id + const_m.id, state_right.input_bit_positions + const_m.input_bit_positions, 128)
        sr_xor_cm = ComponentState([schwaemm.get_current_component_id()], [list(range(128))])

        tmp_rho_1 = rho_1(schwaemm, state_left, M[plaintext_block_count-1])
        tmp_w_128_256 = w_128_256(schwaemm, sr_xor_cm)

        schwaemm.add_XOR_component(tmp_rho_1.id + tmp_w_128_256.id, tmp_rho_1.input_bit_positions + tmp_w_128_256.input_bit_positions, 256)
        tmp1 = ComponentState([schwaemm.get_current_component_id()], [list(range(256))])

        schwaemm.add_concatenate_component(tmp1.id + sr_xor_cm.id, tmp1.input_bit_positions + sr_xor_cm.input_bit_positions, 384)
        sparkle_input = ComponentState([schwaemm.get_current_component_id()], [list(range(384))])

        #schwaemm.add_round_output_component(sparkle_input.id, sparkle_input.input_bit_positions, 384)

        state_left, state_right = sparkle_384_11(schwaemm, sparkle_input)
        #schwaemm.add_round()

    ## Create a tag; Tag = State_Right xor Key
    schwaemm.add_XOR_component(state_right.id + key.id, state_right.input_bit_positions + key.input_bit_positions, 128)
    tag = ComponentState([schwaemm.get_current_component_id()], [list(range(128))])

    ## Output = ciphertext blocks || tag
    ids, pos = get_inputs_parameter(CT + [tag])
    schwaemm.add_cipher_output_component(ids, pos, 256*plaintext_block_count + 128)

    return schwaemm