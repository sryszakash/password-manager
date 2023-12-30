use aes_gcm::Aes256gcm;
   use rand::rngs::OsRng;
   use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};

   fn generate_aes_key() -> GenericArray<u8, <Aes256Gcm as NewAead>::KeySize> {
       let mut key = [0; 32];
       OsRng.fill_bytes(&mut key);
       GenericArray::clone_from_slice(&key)
   }
   
   use aes_gcm::aead::generic_array::GenericArray;
   use aes_gcm::Aes256Gcm;
   use aes_gcm::aead::{Aead, NewAead};

   fn encrypt(data: &[u8], key: &GenericArray<u8, <Aes256Gcm as NewAead>::KeySize>) -> Vec<u8> {
       let cipher = Aes256Gcm::new(key);
       let nonce = GenericArray::from_slice(&[0; 12]); // 12-byte nonce

       let ciphertext = cipher.encrypt(nonce, data).expect("Encryption failed");
       ciphertext
   }

   fn decrypt(ciphertext: &[u8], key: &GenericArray<u8, <Aes256Gcm as NewAead>::KeySize>) -> Vec<u8> {
       let cipher = Aes256Gcm::new(key);
       let nonce = GenericArray::from_slice(&[0; 12]); // 12-byte nonce

       let plaintext = cipher.decrypt(nonce, ciphertext).expect("Decryption failed");
       plaintext
   }

   use std::collections::HashMap;

   struct PasswordManager {
       passwords: HashMap<String, String>,
   }
   
   impl PasswordManager {
       fn new() -> Self {
           PasswordManager {
               passwords: HashMap::new(),
           }
       }
   
       fn add_password(&mut self, username: &str, password: &str) {
           self.passwords.insert(username.to_string(), password.to_string());
       }
   
       fn get_password(&self, username: &str) -> Option<&String> {
           self.passwords.get(username)
       }
   }
   
   fn main() {
       let mut manager = PasswordManager::new();
       manager.add_password("user1", "password1");
       manager.add_password("user2", "password2");
   
       println!("{:?}", manager.get_password("user1"));
       println!("{:?}", manager.get_password("user3"));
   }
   