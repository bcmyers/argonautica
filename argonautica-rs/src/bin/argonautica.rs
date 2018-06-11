extern crate argonautica;

use argonautica::Hasher;

fn main() {
    let mut hasher = Hasher::default();
    let encoded = hasher
        .configure_opt_out_of_secret_key(true)
        .with_password("P@ssw0rd")
        .hash()
        .unwrap();
    println!("{}", &encoded);
}
