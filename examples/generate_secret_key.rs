extern crate failure;
extern crate jasonus;

fn main() -> Result<(), failure::Error> {
    let base64_encoded_secret_key = jasonus::utils::generate_random_base64_encoded_string(32)?;
    println!("{}", &base64_encoded_secret_key);
    Ok(())
}
