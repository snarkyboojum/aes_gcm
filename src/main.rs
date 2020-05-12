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

// assume big endian
fn u8_to_u128(bytes: &[u8]) -> u128 {
    assert_eq!(bytes.len(), 16);

    let mut output = 0u128;
    for (i, &byte) in bytes.iter().rev().enumerate() {
        // println!("shifting byte: {}, by: {}", byte, i * 8);
        output |= (byte as u128) << (i * 8);
        // println!("output: {:b}", output);
    }

    // println!("bytes: {:?}", bytes);
    // println!("output: {:?}", output);

    output
}

// assumes length of bit_string >= s
// increments the right most s bits of the string see p11, spec[1]
fn inc_s(bit_string: &[u8], s: u32, output: &[u8]) {}

// multiplication operation on blocks, see p11 of Ref[1]
// takes 128 bit blocks, builds the product and returns it (as a 128 bit block)
//
fn mul_blocks(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    let R = 225u128 << 120; // R is 11100001 || 0(120), see spec[1]

    for i in 0..128 {
        let xi_bit = (x >> i) & 1;
        let vi_bit = (v >> i) & 1;
        let zi_bit = (z >> i) & 1;

        if xi_bit == 0 {
            z |= zi_bit << (i + 1);
        } else {
            z |= (zi_bit ^ vi_bit) << (i + 1);
        }

        // if lsb is 1
        if v & 1 == 0 {
            v |= vi_bit >> 1;
        } else {
            v |= (vi_bit >> 1) ^ R;
        }
    }

    z
}

// GHASH function, see p12 of Ref[1]
// takes an integer m multiple of 128 bit strings, i.e. m x 128
// for m > 0 (some positive integer)
fn ghash(hash_subkey: u128, bit_string: &[u128]) -> u128 {
    let mut y = 0u128;
    let m = bit_string.len();

    // TODO: do proper error handling here
    assert!(m > 0);

    for i in 1..m {
        let yi = mul_blocks(y ^ bit_string[i - 1], hash_subkey);
        y = yi;
    }

    y
}

// we use the AES-128 bit cipher, see p13 of Ref[1]
fn gctr(counter_block: &[u8], bit_string: &[u8], output: &mut [u8]) {
    // TODO: the dream would be to parallelise as much as possible here - bit string into n * 128 bit blocks

    // check for "empty" bit string - is this null or something else?
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
    // TODO: this is all just faking it for now - we need to deal with a real key
    // apply cipher to the "zero" block
    let key_schedule = [0u32; 4 * (aes_crypt::Rounds::Ten as usize + 1)];

    // convert to a u128
    let hash_bytes_subkey = aes_crypt::cipher(&[0u8; 16], &key_schedule);
    // TODO: this assume big endian architecture
    let hash_subkey = u8_to_u128(&hash_bytes_subkey);

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
    fn test_u8_to_u128() {
        let mut bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(u8_to_u128(&bytes), 1);

        bytes = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(u8_to_u128(&bytes), 2u128.pow(120));
    }
    #[test]
    fn test_mul_blocks() {}

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
