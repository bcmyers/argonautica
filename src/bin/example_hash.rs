extern crate a2;

fn main() {
    let mut hasher = a2::Hasher::default();
    let hash = hasher
        .with_password("P@ssw0rd")
        .with_secret_key(
            "\
             secret key that you should really store in \
             an environment variable instead of in code, \
             but this is just an example\
             ",
        )
        .hash()
        .unwrap();
    println!("{}", &hash);
    // 👆 prints a hash, which will be random since the default Hasher uses a random salt
}
