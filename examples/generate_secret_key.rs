extern crate a2;

fn main() -> Result<(), a2::Error> {
    let base64_encoded_secret_key = a2::utils::generate_random_base64_encoded_string(32)?;
    println!("{}", &base64_encoded_secret_key);
    Ok(())
}
