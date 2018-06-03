extern crate a2;

// fn main() {
//     let password = "P@ssw0rd".to_string();
//     let secret_key = "\
//         secret key that you should really store in \
//         an environment variable instead of in code, \
//         but this is just an example".to_string();

//     let mut hasher = a2::Hasher::default();
//     let hash = hasher
//         .with_password(password)
//         .with_secret_key(secret_key)
//         .hash()
//         .unwrap();

//     println!("{}", &hash);
//     // 👆 prints a hash, which will be random since the default Hasher uses a random salt
// }
fn main() {
    let password = "P@ssw0rd".to_string();
    let secret_key = "\
                      secret key that you should really store in \
                      an environment variable instead of in code, \
                      but this is just an example"
        .to_string();

    let mut verifier = a2::Verifier::default();
    let is_valid = verifier
        .with_hash(
            "
            $argon2id$v=19$m=4096,t=128,p=2$\
            539gu1a/qkTRCHKPuECV7jcRgWH/hRDjxidNdQJ7cKs$\
            On6oPYf4jttaWb4kRCyyffDVYkBF+R4cEBl8WADZhw0\
        ",
        )
        .with_password(password)
        .with_secret_key(secret_key)
        .verify()
        .unwrap();

    assert!(is_valid);
}
