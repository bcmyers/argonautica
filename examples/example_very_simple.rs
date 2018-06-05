extern crate jasonus;

fn main() -> Result<(), jasonus::Error> {
    let mut hasher = jasonus::Hasher::default();
    let hash = hasher
        .with_password("P@ssw0rd")
        .with_secret_key(
            "\
             secret key that you should really store in \
             an environment variable instead of in code, \
             but this is just an example\
             ",
        )
        .hash()?;

    println!("{}", &hash);
    // 👆 prints a hash, which will be random since the default Hasher uses a random salt

    let mut verifier = jasonus::Verifier::default();
    let is_valid = verifier
        .with_hash(&hash)
        .with_password("P@ssw0rd")
        .with_secret_key(
            "\
             secret key that you should really store in \
             an environment variable instead of in code, \
             but this is just an example\
             ",
        )
        .verify()?;

    assert!(is_valid);

    Ok(())
}
