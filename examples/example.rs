extern crate a2;
extern crate failure;

fn main() {
    run().unwrap();
}

fn run() -> Result<(), failure::Error> {
    match a2::utils::fails_on_purpose() {
        Ok(_) => (),
        Err(e) => {
            println!("Debug: {:?}", e);
            println!("{:#?}", e);
            println!("Display: {}", e);
        }
    }
    a2::utils::fails_on_purpose()?;
    Ok(())
}
