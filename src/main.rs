use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use rand::Rng;
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray,
};
use aes::NewBlockCipher;

// Use AES encryption to encrypt the data
fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // let mut padded_data = vec![0; (data.len() + 15) & !15];
    // padded_data[..data.len()].copy_from_slice(data);
    let mut padding_len = 16 - (data.len() % 16);
    if padding_len == 0 {
        padding_len = 16;
    }
    let mut padded_data = vec![0; data.len() + padding_len];
    padded_data[..data.len()].copy_from_slice(data);
    let mut rng = rand::thread_rng();
    for i in data.len()..padded_data.len() {
        padded_data[i] = rng.gen();
    }
    let key_array = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key_array);
    let mut encrypted_data = vec![0; padded_data.len()];
    for chunk in padded_data.chunks_exact(16) {
        let block = GenericArray::from_slice(chunk);
        let mut data_block = block.clone();
        cipher.encrypt_block(&mut data_block);
        encrypted_data[..16].copy_from_slice(&data_block);
    }
    encrypted_data
}

// Use AES encryption to decrypt the data
fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let key_array = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key_array);
    let mut decrypted_data = vec![0; data.len()];
    for chunk in data.chunks_exact(16) {
        let block = GenericArray::from_slice(chunk);
        let mut data_block = block.clone();
        cipher.decrypt_block(&mut data_block);
        decrypted_data[..16].copy_from_slice(&data_block);
    }
    let mut padding_len = 0;
    for i in (data.len() - 16)..data.len() {
        let padding = decrypted_data[i];
        if padding == 0 {
            padding_len += 1;
        }
    }
    let decrypted_data_len = decrypted_data.len() - padding_len;
    decrypted_data.truncate(decrypted_data_len);
    decrypted_data
}

// Hide the encrypted data inside the image file
fn hide_data(image_file: &str, data: &[u8], key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(image_file);
    let _display = path.display();

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

    

    let data_len = std::cmp::min(encrypted_data.len(), image.len());


    let mut rng = rand::thread_rng();
    let offset = rng.gen_range(0..image.len());
    if offset + encrypted_data.len() >= image.len() {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Data to be encrypted is larger than the image.")));
    }

    // Use the least significant bit of each pixel to store the encrypted data
    for (i, b) in encrypted_data.iter().enumerate() {
        let pixel = (i * 4) + offset;
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
    let _display = path.display();

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
    let offset = rng.gen_range(0..image.len());

    let encrypted_data_len = (image.len() - offset) / 8;
    let mut encrypted_data = vec![0; encrypted_data_len];


    if encrypted_data.len() * 8 <= image.len() {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Data to be encrypted is larger than the image.")));
    }

    // Extract the encrypted data from the least significant bit of each pixel
    for (i, b) in (offset..image.len()).enumerate() {
        let _pixel = (i * 8) + offset;
        let least_significant_bit = (image[b] & 1) << (i % 8);
        encrypted_data[i / 8] |= least_significant_bit;
    }

    // Trim the padded zeros from the encrypted data
    let encrypted_data = encrypted_data.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();

    let decrypted_data = decrypt(&encrypted_data, key);

    Ok(decrypted_data)
}

fn main() {
    hide_data("demo.png", b"secret message", b"hacker");
}
