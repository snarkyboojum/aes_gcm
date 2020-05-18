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
    assert!(bytes.len() <= 16);

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

// get the left-most 's' bits in bytes
fn msb_s(s: usize, bytes: &[u8], result: &mut Vec<u8>) {
    assert!(bytes.len() * 128 >= s);

    // println!("msb for {} bits", s);
    let num_bytes = s / 8;
    let bits_remainder = s % 8;

    for i in 0..num_bytes {
        result.push(bytes[i]);
    }
    // if there are bits that spill over a block boundary
    // use a mask to grab it , e.g. byte & 0xf0
    if bits_remainder != 0 {
        // println!("bits remainder: {:b}", bits_remainder);
        // println!("pulling from byte num: {}", num_bytes);
        let remainder = bytes[num_bytes] >> (8 - bits_remainder);
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
fn gctr(key_schedule: &[u32; 44], counter_block: u128, bit_string: &[u8], output: &mut Vec<u8>) {
    // don't need to explicitly check for an empty bit_string here - as output will be empty by default
    if bit_string.len() == 0 {
        return;
    }

    // TODO: I think this just gives us the upper bound on number of 128 bit blocks
    //       which we don't need because we're chunking below
    // this gives us the ceiling for integer division
    // let n = ((bit_string.len() * 8) + 128 - 1) / 128;
    let mut cb = counter_block;

    // need to gather bytes in bit_string into 128 bit blocks. Use chunks() which
    // will also give us a partial block (if necessary) at the end
    for (b, block) in bit_string.chunks(16).enumerate() {
        println!("Block: {:?}", block);

        let mut y = 0u128;

        // cater for a partial block
        if block.len() < 16 {
            let mut msb = Vec::<u8>::new();
            msb_s(
                block.len() * 8,
                &aes_crypt::cipher(&cb.to_be_bytes(), key_schedule),
                &mut msb,
            );
            y = u8_to_u128(block) ^ u8_to_u128(&msb);
            // TODO: there should be a nicer way to do this
            // grab the correct bytes from the partial block
            output.extend_from_slice(&y.to_be_bytes()[16 - block.len()..16]);
        } else {
            y = u8_to_u128(block) ^ u8_to_u128(&aes_crypt::cipher(&cb.to_be_bytes(), key_schedule));
            output.extend_from_slice(&y.to_be_bytes());
        }
        cb = inc_32(cb);
    }
}

// authenticated encryption algorithm, see p15 of Ref[1] - using AES-128
// returns ciphertext and tag
pub fn gcm_ae(
    key: &[u8],
    iv_bytes: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
    ciphertext: &mut Vec<u8>,
    tag: &mut Vec<u8>,
    tag_size: u32, // do we need tag length (bits) parameterised?
) {
    // build the key schedule for cipher (AES-128)
    let mut key_schedule = [0u32; 4 * (aes_crypt::Rounds::Ten as usize + 1)];
    aes_crypt::expand_key(
        &key,
        &mut key_schedule,
        aes_crypt::KeyLength::OneTwentyEight,
    );
    let hash_bytes_subkey = aes_crypt::cipher(&[0u8; 16], &key_schedule);
    let hash_subkey = u8_to_u128(&hash_bytes_subkey);

    // build the ciphertext
    // pad IV to ensure it is a multiple of 128 bits - assume we'll only work with IVs <= 128 bits
    let mut padded_iv = Vec::<u128>::new();
    assert!(iv_bytes.len() <= 16);

    // build the pre-counter block, j0, to pass to gctr()
    let mut j0 = 0u128;

    let iv = u8_to_u128(iv_bytes);
    if iv_bytes.len() == 12 {
        j0 = iv << 32 | 0x00000001;
    } else {
        let s = 128 * (((iv_bytes.len() * 8) + 128 - 1) / 128) - (iv_bytes.len() * 8);
        padded_iv.push(iv << s);
        padded_iv.push((iv_bytes.len() * 8) as u128);

        j0 = ghash(hash_subkey, &padded_iv);
    }
    gctr(&key_schedule, inc_32(j0), plaintext, ciphertext);

    // build the tag
    let cipher_len = ciphertext.len() * 8;
    let ad_len = additional_data.len() * 8;
    let u = 128 * ((cipher_len + 128 - 1) / 128) - cipher_len;
    let v = 128 * ((ad_len + 128 - 1) / 128) - ad_len;
    println!("u, v: {}, {}", u, v);

    let mut bit_string = Vec::<u8>::new();
    bit_string.extend_from_slice(additional_data);
    bit_string.extend_from_slice(&vec![0x00; v / 8]);
    bit_string.extend_from_slice(ciphertext);
    bit_string.extend_from_slice(&vec![0x00; u / 8]);
    bit_string.extend_from_slice(&((additional_data.len() * 8) as u64).to_be_bytes());
    bit_string.extend_from_slice(&((ciphertext.len() * 8) as u64).to_be_bytes());

    println!("bit_string: {:x?}", bit_string);
    println!("bit_string length: {:?}", bit_string.len());

    let mut bit_string_u128 = Vec::<u128>::new();
    for chunk in bit_string.chunks(16) {
        bit_string_u128.push(u8_to_u128(chunk));
    }

    println!("bit_string_u128: {:x?}", bit_string_u128);
    println!("bit_string_u128 length: {:?}", bit_string_u128.len());

    /*
    let s = ghash(hash_subkey, &bit_string_u128).to_be_bytes();
    let mut full_tag = Vec::<u8>::new();
    gctr(&key_schedule, j0, &s, &mut full_tag);
    msb_s(tag_size as usize, &full_tag, tag);
    */
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

    /*
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
    */

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
        // assert_eq!(test_tag, tag);

        // println!("Ciphertext: {:?}", &test_ct);
        // println!("Tag: {:?}", &test_tag);
    }

    #[test]
    fn test_gcm_ad() {}
}
