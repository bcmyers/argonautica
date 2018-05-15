extern crate a2;

fn main() {
    let mut hasher = a2::Hasher::default();
    let hash = hasher
        .with_password("P@ssw0rd")
        .with_secret_key("somesecretthatyoushouldstoreinanenvironmentvariableinsteadofcode")
        .hash()
        .unwrap();
    println!("{}", &hash);

    let hash = "\
        $argon2id$v=19$m=4096,t=128,p=2\
        $/q7MXPB7VqmB1iRQvgg6g1Vz5Rr76qISATkCGafVnLU\
        $039phOrF/E5yzN67B2aCbXhRAcNMM1yKhhD8wtDMciY\
    ";
    let mut verifier = a2::Verifier::default();
    let is_valid = verifier
        .with_hash(hash)
        .with_password("P@ssw0rd")
        .with_secret_key("somesecretthatyoushouldstoreinanenvironmentvariableinsteadofcode")
        .verify()
        .unwrap();
    println!("{}", is_valid);
}
