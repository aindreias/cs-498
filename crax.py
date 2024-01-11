from claasp.cipher import Cipher 
from claasp.DTOs.component_state import ComponentState

## CRAX-S-10
## To be compared with SPECK 64 / 128

def add_alzette_round(crax: Cipher, x: ComponentState, y: ComponentState, c):
    crax.add_constant_component(32, c)
    const_alzette = ComponentState([crax.get_current_component_id()], [list(range(32))])

    # (x) += ROT((y), 31), (y) ^= ROT((x), 24)
    # (x) ^= (c)
    crax.add_rotate_component(y.id, y.input_bit_positions, 32, 31)
    tmp_y = ComponentState([crax.get_current_component_id()], [list(range(32))])
    crax.add_MODADD_component(x.id + tmp_y.id, x.input_bit_positions + tmp_y.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_rotate_component(x.id, x.input_bit_positions, 32, 24)
    tmp_x = ComponentState([crax.get_current_component_id()], [list(range(32))])
    crax.add_XOR_component(y.id + tmp_x.id, y.input_bit_positions + tmp_x.input_bit_positions, 32)
    y = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_XOR_component(x.id + const_alzette.id, x.input_bit_positions + const_alzette.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    #  (x) += ROT((y), 17), (y) ^= ROT((x), 17)
    #  (x) ^= (c), 
    crax.add_rotate_component(y.id, y.input_bit_positions, 32, 17)
    tmp_y = ComponentState([crax.get_current_component_id()], [list(range(32))])
    crax.add_MODADD_component(x.id + tmp_y.id, x.input_bit_positions + tmp_y.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_rotate_component(x.id, x.input_bit_positions, 32, 17)
    tmp_x = ComponentState([crax.get_current_component_id()], [list(range(32))])
    crax.add_XOR_component(y.id + tmp_x.id, y.input_bit_positions + tmp_x.input_bit_positions, 32)
    y = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_XOR_component(x.id + const_alzette.id, x.input_bit_positions + const_alzette.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    #  (x) += (y),          (y) ^= ROT((x), 31), 
    #  (x) ^= (c),       
    crax.add_MODADD_component(x.id + y.id, x.input_bit_positions + y.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_rotate_component(x.id, x.input_bit_positions, 32, 31)
    tmp_x = ComponentState([crax.get_current_component_id()], [list(range(32))])
    crax.add_XOR_component(y.id + tmp_x.id, y.input_bit_positions + tmp_x.input_bit_positions, 32)
    y = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_XOR_component(x.id + const_alzette.id, x.input_bit_positions + const_alzette.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    #  (x) += ROT((y), 24), (y) ^= ROT((x), 16)
    #  (x) ^= (c)    
    crax.add_rotate_component(y.id, y.input_bit_positions, 32, 24)
    tmp_y = ComponentState([crax.get_current_component_id()], [list(range(32))])
    crax.add_MODADD_component(x.id + tmp_y.id, x.input_bit_positions + tmp_y.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_rotate_component(x.id, x.input_bit_positions, 32, 16)
    tmp_x = ComponentState([crax.get_current_component_id()], [list(range(32))])
    crax.add_XOR_component(y.id + tmp_x.id, y.input_bit_positions + tmp_x.input_bit_positions, 32)
    y = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_XOR_component(x.id + const_alzette.id, x.input_bit_positions + const_alzette.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    return x, y            

def create_crax_instance(number_of_rounds) -> Cipher:
    alzette_constants = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB]

    crax = Cipher("CRAX-S-10", "block cipher", ["plaintext", "key"], [64, 128], 64)

    x = ComponentState(["plaintext"], [list(range(32))])
    y = ComponentState(["plaintext"], [list(range(32, 64))])

    key_0 = ComponentState(["key"], [list(range(32))])
    key_1 = ComponentState(["key"], [list(range(32, 64))])
    key_2 = ComponentState(["key"], [list(range(64, 96))])
    key_3 = ComponentState(["key"], [list(range(96, 128))])

    for step in range(number_of_rounds):
        crax.add_round()
        # x ^= step
        crax.add_constant_component(32, step)
        step_constant = ComponentState([crax.get_current_component_id()], [list(range(32))])
        crax.add_XOR_component(x.id + step_constant.id, x.input_bit_positions + step_constant.input_bit_positions, 32)
        x = ComponentState([crax.get_current_component_id()], [list(range(32))])

        if (step % 2 == 0):
            # x ^= key_0
            crax.add_XOR_component(x.id + key_0.id, x.input_bit_positions + key_0.input_bit_positions, 32)
            x = ComponentState([crax.get_current_component_id()], [list(range(32))])

            # y ^= key_1
            crax.add_XOR_component(y.id + key_1.id, y.input_bit_positions + key_1.input_bit_positions, 32)
            y = ComponentState([crax.get_current_component_id()], [list(range(32))])
        else:
            # x ^= key_2
            crax.add_XOR_component(x.id + key_2.id, x.input_bit_positions + key_2.input_bit_positions, 32)
            x = ComponentState([crax.get_current_component_id()], [list(range(32))])

            # y ^= key_3
            crax.add_XOR_component(y.id + key_3.id, y.input_bit_positions + key_3.input_bit_positions, 32)
            y = ComponentState([crax.get_current_component_id()], [list(range(32))])

        x, y = add_alzette_round(crax, x, y, alzette_constants[step%5])

        if step < (number_of_rounds-1):
            crax.add_round_output_component(x.id + y.id, x.input_bit_positions + y.input_bit_positions, 64)

    # x ^= key_0
    crax.add_XOR_component(x.id + key_0.id, x.input_bit_positions + key_0.input_bit_positions, 32)
    x = ComponentState([crax.get_current_component_id()], [list(range(32))])

    # y ^= key_1
    crax.add_XOR_component(y.id + key_1.id, y.input_bit_positions + key_1.input_bit_positions, 32)
    y = ComponentState([crax.get_current_component_id()], [list(range(32))])

    crax.add_cipher_output_component(x.id + y.id, x.input_bit_positions + y.input_bit_positions, 64)

    return crax