extern crate a2;

use a2::utils;

const SECRET_KEY_LENGTH: u32 = 32;

fn main() {
    let base64_encoded_secret_key = utils::generate_random_base64_encoded_string(SECRET_KEY_LENGTH)
        .expect("failed to generate random base64-encoded string");
    println!("{}", &base64_encoded_secret_key);
}
