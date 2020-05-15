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

// get the right-most 's' bits in blocks
fn lsb_s(s: usize, blocks: &[u128], result: &mut Vec<u128>) {
    assert!(blocks.len() * 128 >= s);

    println!("lsb for {} bits", s);
    let num_blocks = s / 128;
    let bits_remainder = s % 128; //(blocks.len() * 128) % s;

    // push blocks in reverse so we get the "right-most"
    for i in (0..num_blocks).rev() {
        result.push(blocks[i]);
    }

    if bits_remainder != 0 {
        let mask = 2u128.pow(bits_remainder as u32) - 1;
        // println!("mask: {:#2x}", mask);

        // get the 'num_blocks - 1' block from the end and mask it
        let remainder = blocks[blocks.len() - num_blocks - 1] & mask;
        result.push(remainder);
    }
}

// get the left-most 's' bits in blocks
fn msb_s(s: usize, blocks: &[u128], result: &mut Vec<u128>) {
    assert!(blocks.len() * 128 >= s);

    println!("msb for {} bits", s);
    let num_blocks = s / 128;
    let bits_remainder = s % 128; //(blocks.len() * 128) % s;

    for i in 0..num_blocks {
        result.push(blocks[i]);
    }
    // if there are bits that spill over a block boundary
    // use a mask to grab it , e.g. byte & 0xf0
    if bits_remainder != 0 {
        // println!("bits remainder: {:b}", bits_remainder);
        // println!("pulling from block num: {}", num_blocks);
        let remainder = blocks[num_blocks] >> (128 - bits_remainder);
        result.push(remainder);
    }
}

// increments the right-most 32 bits of the bit string by 1
// modulo 2^32 - see p11, spec[1]
fn inc_32(bit_string: u128) -> u128 {
    // get the left most 96 bits
    let msb = bit_string >> 32;

    // take the right most 32 bits and increment by 1, modulo 2^32
    let mut lsb = (bit_string & 0xffffffff) as u32;
    lsb = lsb.wrapping_add(1);

    // put them together
    let result = msb << 32 | lsb as u128;

    result
}

// TODO: not sure if we need this or if we should be internally
// representing padded IV as 128 bit of just bytes
fn pad_iv(bytes: &[u8], padded_iv: &mut [u128]) {}

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
fn gctr(key_schedule: &[u32; 44], counter_block: u128, bit_string: &[u8], output: &mut [u8]) {
    // TODO: the dream would be to parallelise as much as possible here - bit string into n * 128 bit blocks

    // check for "empty" bit string - is this null or something else?
}

// authenticated encryption algorithm, see p15 of Ref[1] - using AES-128
// returns ciphertext and tag
pub fn gcm_ae(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8],
    tag_length: u32, // do we need tag length (bits) parameterised?
) {
    // build the key schedule for cipher (AES-128)
    let mut key_schedule = [0u32; 4 * (aes_crypt::Rounds::Ten as usize + 1)];
    aes_crypt::expand_key(
        &key,
        &mut key_schedule,
        aes_crypt::KeyLength::OneTwentyEight,
    );

    // TODO: this assume big endian architecture - convert to a u128
    // apply cipher to the "zero" block
    let hash_bytes_subkey = aes_crypt::cipher(&[0u8; 16], &key_schedule);
    let hash_subkey = u8_to_u128(&hash_bytes_subkey);

    // build the pre counter block - pad IV isn't a multiple of 128 bits
    let mut padded_iv = Vec::<u128>::new();
    if iv.len() % 16 != 0 {
        pad_iv(&iv, &mut padded_iv);
    }
    // TODO: we need 0(64bits) || iv.len()(64bits) - check this
    padded_iv.push(0u128 | (iv.len() * 8) as u128);
    let counter_block = ghash(hash_subkey, &padded_iv);

    gctr(&key_schedule, inc_32(counter_block), plaintext, ciphertext);
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
    fn test_msb_s() {
        let blocks: &[u128] = &[
            0x00000000000000000000000000000000,
            0xff000000000000000000000000000000,
            0xffa00000000000000000000000000000,
            0xffae0000000000000000000000000000,
        ];

        let mut result = Vec::<u128>::new();
        msb_s(16, blocks, &mut result);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0x00);

        let mut result = Vec::<u128>::new();
        msb_s(144, blocks, &mut result);
        assert_eq!(result.len(), 2);
        assert_eq!(result[1], 0xff00);

        let mut result = Vec::<u128>::new();
        msb_s(133, blocks, &mut result);
        assert_eq!(result.len(), 2);
        assert_eq!(result[1], 0b11111);
    }

    #[test]
    fn test_lsb_s() {
        let blocks: &[u128] = &[
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000000,
            0x0000000000000000000000000000000f,
            0x00000000000000000000000000000000,
        ];

        let mut result = Vec::<u128>::new();
        lsb_s(16, blocks, &mut result);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0x00);

        let mut result = Vec::<u128>::new();
        lsb_s(144, blocks, &mut result);
        assert_eq!(result.len(), 2);
        assert_eq!(result[1], 0x000f);

        let mut result = Vec::<u128>::new();
        lsb_s(133, blocks, &mut result);
        assert_eq!(result.len(), 2);
        assert_eq!(result[1], 0b1111);
    }

    #[test]
    fn test_inc_32() {
        let mut test: u128 = 0x0000000000000000000000000000000f;
        assert_eq!(inc_32(test), 0x00000000000000000000000000000010);

        test = 0x00000000000000000000000000000000;
        assert_eq!(inc_32(test), 0x00000000000000000000000000000001);

        test = 0x000000000000000000000000ffffffff;
        assert_eq!(inc_32(test), 0x00000000000000000000000000000000);

        test = 0x00000000000000000000000effffffff;
        assert_eq!(inc_32(test), 0x00000000000000000000000e00000000);
    }
    #[test]
    fn test_mul_blocks() {}

    #[test]
    fn test_ghash() {}

    #[test]
    fn test_gctr() {}

    #[test]
    fn test_gcm_ae() {
        use hex::FromHex;
        let key = Vec::from_hex("c608316f809e3c54f3272a18256a5fec").expect("Couldn't parse key");
        let iv = Vec::from_hex("38f4ec6b2c1c197bf6e0e994").expect("Couldn't parse IV");
        let ct = Vec::from_hex("659228b6282c2226c755136a9fc1bcacdc8cb640660cc784a841b5c385f34302a8bc5c0bd30b982d1b641bf642d958dddb3d46").expect("Couldn't parse ciphertext");
        let aad = Vec::from_hex("d22804c6a53262ccd930946be718e465").expect("Couldn't parse AAD");
        let tag = Vec::from_hex("ac9ed5212b5623d445d76a5f25e14e").expect("Couldn't parse tag");
        let pt = Vec::from_hex("2fc429740460dd0bea16bfe314d3258f6708b5ebb8ad2c4afd4d11fe99646227abe997f0688fc0e3f1c7c0462dc9254dbebfb0").expect("Couldn't parse plaintext");

        let mut test_tag = Vec::<u8>::new();
        let mut test_ct = Vec::<u8>::new();

        gcm_ae(&key, &iv, &pt, &aad, &mut test_ct, &mut test_tag, 120);

        assert_eq!(test_ct, ct);
        assert_eq!(test_tag, tag);

        // println!("Ciphertext: {:?}", &test_ct);
        // println!("Tag: {:?}", &test_tag);
    }

    #[test]
    fn test_gcm_ad() {}
}
