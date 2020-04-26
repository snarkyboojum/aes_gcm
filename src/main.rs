/*
References:

[1] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

Implementation notes:

Authenticated encryption function

Input data:
 - plaintext, P
 - additional authenticated data (AAD), A
 - initialisation vector (IV), IV (basically a nonce)

GCM protects the authenticity of both P, and A, and the confidentiality of P.

len(P) <= 2.pow(39) - 256
len(A) <= 2.pow(64) - 1
1 <= len(IV) <= 2.pow(64) - 1

GCM is defined on bit strings, where all strings are multiples of 8 (i.e. bytes)

Recommendation is to support IVs that are up to but not longer than 96 bits.

Output data:
 - ciphertext, C (same bit length as P)
 - authentication tag (tag), T (of length 128, 120, 112, 104, 96, or even 64, 32 bits)


Authenticated decryption function

Inputs:
 - IV, A, C, T

Outputs:
 - P (plaintext corresponding to C)
 - FAIL (if error) - which is a special error code

*/

pub enum Authenticity {
    Pass,
    Fail,
}

// this assume big endianess
fn lsb(byte: u8) -> bool {
    let lsb = byte & 1;
    lsb == 1
}

fn msb(byte: u8) -> bool {
    let msb = (byte >> 7) & 1;
    msb == 1
}

fn get_bit(byte: u8, pos: usize) -> bool {
    let bit = (byte >> pos) & 1;
    bit == 1
}

fn print_bits(bytes: &[u8]) {
    for b in bytes {
        print!("{:b}", b);
    }
    print!("\n");
}

fn set_bit(byte: &mut u8, pos: usize, bit: bool) {}

// multiplication operation on blocks, see p11 of Ref[1]
// takes 128 bit blocks, builds the product and returns it (as a 128 bit block)
//
// TODO : currently implemented as an array of bytes, but should probably use
// 127 bit usigned ints
fn mul_block(x: &[u8; 16], y: &[u8; 16], output: &mut [u8; 16]) {
    let mut z = [0u8; 16];
    let mut v = *y;

    let mut R = [0u8; 16];
    R[1] = 0b11100001; // R is 11100001 || 0(120) as per spec[1]
                       // print_bits(&R);

    // looping 'bitwise', but over an array of bytes
    for i in 0..128 {
        let byte_offset = i / 8;
        let bit_offset = i % 8;

        let x_bit = get_bit(x[byte_offset], bit_offset);
        let z_bit = get_bit(z[byte_offset], bit_offset);
        let v_bit = get_bit(v[byte_offset], bit_offset);

        if x_bit {
            if bit_offset == 7 {
                set_bit(&mut z[byte_offset + 1], 0, z_bit);
            } else {
                set_bit(&mut z[byte_offset], bit_offset + 1, z_bit);
            }
        } else {
            // TODO: is this right? does xor'ing bool work?
            if bit_offset == 7 {
                set_bit(&mut z[byte_offset + 1], 0, z_bit ^ v_bit);
            } else {
                set_bit(&mut z[byte_offset], bit_offset + 1, z_bit ^ v_bit);
            }
        }

        if !lsb(v[i]) {
            v[i + 1] = v[i] >> 1;
        }
        if lsb(v[i]) {
            // v[i + 1] = (v[i] >> 1) ^ R;
        }
    }
    assert_eq!(x.len(), 16);
    assert_eq!(y.len(), 16);
}

// GHASH function, see p12 of Ref[1]
// takes an integer m multiple of 128 bit strings, i.e. m x 128
fn ghash(bit_string: &[u8], output: &mut [u8]) {}

// we use the AES-128 bit cipher, see p13 of Ref[1]
fn gctr(counter_block: &[u8], bit_string: &[u8], output: &mut [u8]) {
    // TODO: parallelise as much as possible here - bit string into n * 128 bit blocks
}

// authenticated encryption algorithm, see p15 of Ref[1] - using AES-128
// returns ciphertext and tag
pub fn gcm_ae(
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8],
) {
    // apply cipher to the "zero" block
    let key_schedule = [0u32; 4 * (aes_crypt::Rounds::Ten as usize + 1)];
    let hash_subkey = aes_crypt::cipher(&[0u8; 16], &key_schedule);

    // generate the key from the IV
    let counter_block = [0u8; 16];
    let mut ciphertext = [0u8; 16];
    gctr(&counter_block, plaintext, &mut ciphertext);
}

// authenticated decryption, see p16 of Ref[1] - using AES-128
// returns plaintext and an Authenticity flag - Pass or Fail
pub fn gcm_ad(
    iv: &[u8],
    ciphertext: &[u8],
    additional_data: &[u8],
    tag: &[u8],
    plaintext: &mut [u8],
) -> Authenticity {
    return Authenticity::Pass;
}

fn main() {
    println!(r#"Welcome to the GCM mode for AES (128)!"#);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msb() {
        let mut byte = 0b10011001;
        assert_eq!(msb(byte), true);

        byte = 0b01011001;
        assert_eq!(msb(byte), false);
    }

    #[test]
    fn test_lsb() {
        let mut byte = 0b10011001;
        assert_eq!(lsb(byte), true);

        byte = 0b00011000;
        assert_eq!(lsb(byte), false);
    }

    #[test]
    fn test_get_bit() {
        let byte = 0b10011010;
        assert_eq!(get_bit(byte, 3), true);
        assert_eq!(get_bit(byte, 7), true);
        assert_eq!(get_bit(byte, 1), true);
        assert_eq!(get_bit(byte, 0), false);
    }
    #[test]
    fn test_mul_block() {}

    #[test]
    fn test_ghash() {}

    #[test]
    fn test_gctr() {}

    #[test]
    fn test_gcm_ae() {
        /*
        Key = c608316f809e3c54f3272a18256a5fec
        IV = 38f4ec6b2c1c197bf6e0e994
        CT = 659228b6282c2226c755136a9fc1bcacdc8cb640660cc784a841b5c385f34302a8bc5c0bd30b982d1b641bf642d958dddb3d46
        AAD = d22804c6a53262ccd930946be718e465
        Tag = ac9ed5212b5623d445d76a5f25e14e
        PT = 2fc429740460dd0bea16bfe314d3258f6708b5ebb8ad2c4afd4d11fe99646227abe997f0688fc0e3f1c7c0462dc9254dbebfb0
        */
    }

    #[test]
    fn test_gcm_ad() {}
}
