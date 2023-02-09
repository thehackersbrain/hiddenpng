find bugs in the program and generate the code snippets with the replacement lines

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use rand::Rng;
use rand::RngCore;
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::BlockMode;

// Use AES encryption to encrypt the data
fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key);
    cipher.encrypt_vec(data, Pkcs7)
}

// Use AES encryption to decrypt the data
fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key);
    cipher.decrypt_vec(data, Pkcs7)
}

// Hide the encrypted data inside the image file
fn hide_data(image_file: &str, data: &[u8], key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(image_file);
    let display = path.display();

    let mut file = match File::open(&path) {
        Err(why) => return Err(Box::new(why)),
        Ok(file) => file,
    };

    let mut image = Vec::new();
    match file.read_to_end(&mut image) {
        Err(why) => return Err(Box::new(why)),
        Ok(_) => (),
    };

    let encrypted_data = encrypt(data, key);

    if encrypted_data.len() > image.len() {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Data to be encrypted is larger than the image.")));
    }

    let mut rng = rand::thread_rng();
    let offset = rng.gen_range(0, image.len());

    // Use the least significant bit of each pixel to store the encrypted data
    for (i, b) in encrypted_data.iter().enumerate() {
        let pixel = (i * 8) + offset;
        let color_value = image[pixel];
        let new_color_value = color_value ^ (*b as u8);
        image[pixel] = new_color_value;
    }

    let mut file = match File::create(&path) {
        Err(why) => return Err(Box::new(why)),
        Ok(file) => file,
    };

    match file.write_all(&image) {
        Err(why) => return Err(Box::new(why)),
        Ok(_) => (),
    };

    Ok(())
}

// Extract the data from the image file
fn extract_data(image_file: &str, key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = Path::new(image_file);
    let display = path.display();

    let mut file = match File::open(&path) {
        Err(why) => return Err(Box::new(why)),
        Ok(file) => file,
    };

    let mut image = Vec::new();
    match file.read_to_end(&mut image) {
        Err(why) => return Err(Box::new(why)),
        Ok(_) => (),
    };

    let mut rng = rand::thread_rng();
    let offset = rng.gen_range(0, image.len());

    let mut encrypted_data = vec![0; image.len()];

    if encrypted_data.len() * 8 > image.len() {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Data to be encrypted is larger than the image.")));
    }

    // Extract the encrypted data from the least significant bit of each pixel
    for (i, b) in image[offset..].iter().enumerate() {
        let pixel = (i * 8) + offset;
        let least_significant_bit = (*b & 1) << (i % 8);
        encrypted_data[i / 8] |= least_significant_bit;
    }

    // Trim the padded zeros from the encrypted data
    let mut encrypted_data = encrypted_data.into_iter().take_while(|&x| x != 0).collect();

    let decrypted_data = decrypt(&encrypted_data, key);

    Ok(decrypted_data)
}

fn main() {
    println!("Hello World");
}