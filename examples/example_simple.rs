extern crate a2;
extern crate failure;

fn main() {
    run().unwrap();
}

fn run() -> Result<(), failure::Error> {
    let mut hasher = a2::Hasher::default()?;
    let hash = hasher
        .with_password("P@ssw0rd")
        .with_secret_key("secret")
        .hash()?;
    println!("{}", &hash);

    let mut verifier = a2::Verifier::default();
    let is_valid = verifier
        .with_hash(&hash)
        .with_password("P@ssw0rd")
        .with_secret_key("secret")
        .verify()?;

    assert!(is_valid);
    Ok(())
}
