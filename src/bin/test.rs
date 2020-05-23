extern crate aes_gcm;

use aes_gcm::gcm_ae;

fn main() {
    println!(r#"Welcome to the GCM mode for AES (128)!"#);

    use hex::FromHex;

    // TODO: write a test harness to parse and run each test in
    // test_vectors/gcmEncryptExtIV128.rsp and test_vectors/gcmDecrypt128.rsp

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

    println!("Cipher text: {:x?}", test_ct);
    println!("Tag: {:02x?}", tag);
}
