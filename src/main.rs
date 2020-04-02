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

enum Authenticity {
    Pass,
    Fail,
}

// multiplication operation on blocks, see p11 of Ref[1]
// takes 128 bit blocks, builds the product and returns it (as a 128 bit block)
fn mul_block(block1: &[u8], block2: &[u8], output: &mut [u8]) {}

// GHASH function, see p12 of Ref[1]
// takes an integer m multiple of 128 bit strings, i.e. m x 128
fn ghash(bit_string: &[u8], output: &mut [u8]) {}

// we use the AES-128 bit cipher, see p13 of Ref[1]
fn gctr(counter_block: &[u8], bit_string: &[u8], output: &mut [u8]) {}

// authenticated encryption algorithm, see p15 of Ref[1] - using AES-128
// returns ciphertext and tag
fn gcm_ae(
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8],
) {
}

// authenticated decryption, see p16 of Ref[1] - using AES-128
// returns plaintext and an Authenticity flag - Pass or Fail
fn gcm_ad(
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
