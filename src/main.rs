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

// multiplication operation on blocks, see p11 of Ref[1]
// takes 128 bit blocks, builds the product and returns it (as a 128 bit block)
fn mul_block(x: &[u8], y: &[u8], output: &mut [u8]) {
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
