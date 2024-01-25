extern crate bip39;
use bip39::{Language, Mnemonic};
use hex::encode;
use pbkdf2::pbkdf2_hmac_array;
use rand::Rng;
use sha2::Sha512;

fn main() {
    // generate 128bits entropy
    let rng: [u8; 16] = rand::thread_rng().gen();

    let mnomonic = Mnemonic::from_entropy_in(Language::English, &rng);

    // extract code words
    let mnemonic_code_words: Vec<&str> = mnomonic.clone().unwrap().word_iter().collect();

    // key stretching function
    let pbkdf2_hmac_sha512_key_stretching_function =
        pbkdf2_hmac_array::<Sha512, 64>(&mnomonic.unwrap().to_entropy(), b"", 2048);

    // seed
    let seed = encode(pbkdf2_hmac_sha512_key_stretching_function);
    println!("{:#?}", mnemonic_code_words);
    println!("{}", seed,);
}
