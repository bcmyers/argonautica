extern crate a2;
extern crate failure;

fn main() -> Result<(), failure::Error> {
    let mut verifier = a2::Verifier::default();
    let is_valid = verifier
        .with_hash("$argon2id$v=19$m=4096,t=128,p=2$c29tZXNhbHQ$WwD2/wGGTuw7u4BW8sLM0Q")
        .with_password("P@ssw0rd")
        .verify()?;
    println!("{}", is_valid);
    Ok(())
}
