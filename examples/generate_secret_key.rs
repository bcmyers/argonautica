extern crate jasonus;

fn main() -> Result<(), jasonus::Error> {
    let base64_encoded_secret_key = jasonus::utils::generate_random_base64_encoded_string(32)?;
    println!("{}", &base64_encoded_secret_key);
    Ok(())
}
