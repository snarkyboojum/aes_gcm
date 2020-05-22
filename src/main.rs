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

#[derive(PartialEq, Debug)]
pub enum Authenticity {
    Pass,
    Fail,
}

// assume big endian
fn u8_to_u128(bytes: &[u8]) -> u128 {
    assert!(bytes.len() <= 16);

    let mut output = 0u128;
    for (i, &byte) in bytes.iter().rev().enumerate() {
        output |= (byte as u128) << (i * 8);
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

    // do this in reverse, because bit strings are treated as little endian
    for i in (0..128).into_iter().rev() {
        let xi_bit = (x >> i) & 1;
        let vi_bit = (v >> i) & 1;
        let zi_bit = (z >> i) & 1;

        /*
        println!(
            "i: {}, z: {:0128b}, zi_bit: {}, vi_bit: {}, xi_bit: {}",
            i, z, zi_bit, vi_bit, xi_bit
        );
        */

        if xi_bit != 0 {
            z = z ^ v
        }

        // if lsb is 1
        if v & 1 == 0 {
            v = v >> 1;
        } else {
            v = (v >> 1) ^ R;
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

    for i in 0..m {
        let yi = mul_blocks(y ^ bit_string[i], hash_subkey);
        y = yi;
    }

    println!("y: {:x?}", y);
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
    for block in bit_string.chunks(16) {
        println!("Block: {:x?}", block);

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

// build key schedule and hash subkey with 0 block
fn hash_subkey(key: &[u8], key_schedule: &mut [u32]) -> u128 {
    // build the key schedule for cipher (AES-128)
    aes_crypt::expand_key(&key, key_schedule, aes_crypt::KeyLength::OneTwentyEight);
    let hash_bytes_subkey = aes_crypt::cipher(&[0u8; 16], &key_schedule);
    let hash_subkey = u8_to_u128(&hash_bytes_subkey);

    hash_subkey
}

// pad IV to ensure it is a multiple of 128 bits - assume we'll only work with IVs <= 128 bits
fn init_iv(iv_bytes: &[u8], hash_subkey: u128) -> u128 {
    assert!(iv_bytes.len() <= 16);

    let mut padded_iv = Vec::<u128>::new();
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

    j0
}

fn build_tag(
    additional_data: &[u8],
    ciphertext: &mut [u8],
    hash_subkey: u128,
    key_schedule: &[u32; 44],
    j0: u128,
    tag: &mut Vec<u8>,
    tag_size: usize,
) {
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
    bit_string.extend_from_slice(&(ad_len as u64).to_be_bytes());
    bit_string.extend_from_slice(&(cipher_len as u64).to_be_bytes());

    println!("computed j0: {:x?}", j0);
    println!("ad length: {:?}", additional_data.len());
    println!("ciphertext length: {:?}", ciphertext.len());

    let mut bit_string_u128 = Vec::<u128>::new();
    for chunk in bit_string.chunks(16) {
        bit_string_u128.push(u8_to_u128(chunk));
    }

    println!("bit_string_u128: {:x?}", bit_string_u128);
    println!("bit_string_u128 length: {:?}", bit_string_u128.len());

    println!("ct: {:x?}", ciphertext);
    let s = ghash(hash_subkey, &bit_string_u128).to_be_bytes();
    println!("s: {:x?}", s);

    let mut full_tag = Vec::<u8>::new();
    gctr(key_schedule, j0, &s, &mut full_tag);
    println!("full_tag: {:x?}", full_tag);

    msb_s(tag_size, &full_tag, tag);
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
    tag_size: usize, // do we need tag length (bits) parameterised?
) {
    // build key schedule and hash subkey with 0 block
    let mut key_schedule = [0u32; 4 * (aes_crypt::Rounds::Ten as usize + 1)];
    let hash_subkey = hash_subkey(key, &mut key_schedule);

    // build the ciphertext
    let j0 = init_iv(&iv_bytes, hash_subkey);
    gctr(&key_schedule, inc_32(j0), plaintext, ciphertext);

    // build the tag
    let tag = build_tag(
        additional_data,
        ciphertext,
        hash_subkey,
        &key_schedule,
        j0,
        tag,
        tag_size,
    );

    println!("tag: {:x?}", tag);
}

// authenticated decryption, see p16 of Ref[1] - using AES-128
// returns plaintext and an Authenticity flag - Pass or Fail
pub fn gcm_ad(
    key: &[u8],
    iv_bytes: &[u8],
    ciphertext: &mut [u8],
    additional_data: &[u8],
    tag: &mut Vec<u8>,
    tag_size: usize,
    plaintext: &mut Vec<u8>,
) -> Authenticity {
    // TODO: check that IV, A and C are of supporting bit lengths
    if tag.len() * 8 != tag_size {
        return Authenticity::Fail;
    }

    // build key schedule and hash subkey with 0 block
    let mut key_schedule = [0u32; 4 * (aes_crypt::Rounds::Ten as usize + 1)];
    let hash_subkey = hash_subkey(key, &mut key_schedule);

    // build the plaintext
    let j0 = init_iv(&iv_bytes, hash_subkey);
    gctr(&key_schedule, inc_32(j0), ciphertext, plaintext);

    // compute the tag
    let mut computed_tag = Vec::<u8>::new();
    build_tag(
        additional_data,
        ciphertext,
        hash_subkey,
        &key_schedule,
        j0,
        &mut computed_tag,
        tag_size,
    );

    if *tag == computed_tag {
        return Authenticity::Pass;
    } else {
        return Authenticity::Fail;
    }
}

fn main() {
    println!(r#"Welcome to the GCM mode for AES (128)!"#);
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[ignore]
    fn test_msb_s() {
        let blocks: &[u28] = &[
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
    #[ignore]
    fn test_mul_blocks() {}

    #[test]
    #[ignore]
    fn test_ghash() {}

    #[test]
    #[ignore]
    fn test_gctr() {}

    #[test]
    fn test_gcm_ae() {
        use hex::FromHex;

        let key = Vec::from_hex("02f4ecf5fd34c1c809aeb6bf89fdc854").expect("Couldn't parse key");
        let iv = Vec::from_hex("604fd7150dab208356842a52").expect("Couldn't parse IV");
        let ct = Vec::from_hex("a024576d47748eca6ad23668652896d75948a5e7120d544746efb30ffbc9a264a460c0296cb290513f0788c6892cbf69193a6d").expect("Couldn't parse ciphertext");
        let aad = Vec::from_hex("e4b76c7274e732cd3c422c909150a056").expect("Couldn't parse AAD");
        let tag = Vec::from_hex("03ab31b8d0095bd0fa389b4de0a087").expect("Couldn't parse tag");
        let pt = Vec::from_hex("5c4e496bae20c0c56054ed7cff3f81e5a550e1a32035033cdab62353b1f624b23ad57ab8ef0c3d74e4d3fddceabf7180e88e15").expect("Couldn't parse plaintext");

        let mut test_tag = Vec::<u8>::new();
        let mut test_ct = Vec::<u8>::new();

        gcm_ae(&key, &iv, &pt, &aad, &mut test_ct, &mut test_tag, 120);

        assert_eq!(test_ct, ct);
        assert_eq!(test_tag, tag);
    }

    #[test]
    fn test_gcm_ad() {
        use hex::FromHex;

        // authenticated decryption that fails
        let key = Vec::from_hex("f5a0b1639c67c7760109056a3a329804").expect("Couldn't parse key");
        let iv = Vec::from_hex("e1b75506d66509a52f0960f7").expect("Couldn't parse IV");
        let mut ct = Vec::from_hex("4d8738341660f7e49ca1ddf7db1255c1eca46b947fa80134340d364e611255194f3261413a82e763720ef81dedc8b10bed3b30").expect("Couldn't parse ciphertext");
        let aad = Vec::from_hex("8421f67419d3d37cc9e97b712b8b0924").expect("Couldn't parse AAD");
        let mut tag = Vec::from_hex("d7c586892b2e6ad60c2106a8").expect("Couldn't parse tag");

        let mut test_pt = Vec::<u8>::new();
        let result = gcm_ad(&key, &iv, &mut ct, &aad, &mut tag, 96, &mut test_pt);
        assert_eq!(result, Authenticity::Fail);

        // authenticated decryption test that passes
        let key = Vec::from_hex("a42c74c1284bf27573f57da53ebeab79").expect("Couldn't parse key");
        let iv = Vec::from_hex("7cf56f16a053de804ee7e2e7").expect("Couldn't parse IV");
        let mut ct = Vec::from_hex("12053dcbeda87a9f896c12503ca48d7a47496255282869bd6e09547a07b13f7ea40ba295028f728430af6613d9258034b219af").expect("Couldn't parse ciphertext");
        let aad = Vec::from_hex("654c9eefee483089370c3932268bbfb9").expect("Couldn't parse AAD");
        let mut tag = Vec::from_hex("268777ddc8caffad4a50cc53").expect("Couldn't parse tag");
        let pt = Vec::from_hex("854b6ec0c014ef38113cea5a9a1101e96a7110738cb38a8a512e85b4cedb235e2a030b4d38108173e1f20e09c0a4de7624466e").expect("Couldn't parse plaintext");

        let mut test_pt = Vec::<u8>::new();
        let result = gcm_ad(&key, &iv, &mut ct, &aad, &mut tag, 96, &mut test_pt);
        assert_eq!(test_pt, pt);
        assert_eq!(result, Authenticity::Pass);
    }
}
