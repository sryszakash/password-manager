// Import the required crates
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use bcrypt::{hash, verify};

// Define the data structures for the requests and responses
#[derive(Serialize, Deserialize)]
struct CreateAccountRequest {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct CreateAccountResponse {
    status: String,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct LoginResponse {
    status: String,
    message: String,
    token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CreatePasswordRequest {
    token: String,
    site: String,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct CreatePasswordResponse {
    status: String,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct GetPasswordsRequest {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct Password {
    site: String,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct GetPasswordsResponse {
    status: String,
    message: String,
    passwords: Option<Vec<Password>>,
}

// Define the encryption and decryption functions
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Encrypt a plaintext with a key and an iv
fn encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext);
    ciphertext
}

// Decrypt a ciphertext with a key and an iv
fn decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    let plaintext = cipher.decrypt_vec(ciphertext).unwrap();
    plaintext
}

// Define the handler functions for the API endpoints
// Create a new account with a username and a password
async fn create_account(
    pool: web::Data<PgPool>,
    req: web::Json<CreateAccountRequest>,
) -> impl Responder {
    // Check if the username already exists in the database
    let row = sqlx::query!("select * from accounts where username = $1", req.username)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap();

    if let Some(_) = row {
        // Return an error response if the username is taken
        return HttpResponse::Ok().json(CreateAccountResponse {
            status: "error".to_string(),
            message: "Username already exists".to_string(),
        });
    }

    // Hash the password with bcrypt
    let hashed_password = hash(&req.password, 10).unwrap();

    // Insert the username and the hashed password into the database
    sqlx::query!("insert into accounts (username, password) values ($1, $2)", req.username, hashed_password)
        .execute(pool.get_ref())
        .await
        .unwrap();

    // Return a success response
    HttpResponse::Ok().json(CreateAccountResponse {
        status: "success".to_string(),
        message: "Account created".to_string(),
    })
}

// Login with a username and a password and get a token
async fn login(
    pool: web::Data<PgPool>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    // Get the account from the database by the username
    let row = sqlx::query!("select * from accounts where username = $1", req.username)
        .fetch_optional(pool.get_ref())
        .await
        .unwrap();

    if let Some(account) = row {
        // Verify the password with bcrypt
        let is_valid = verify(&req.password, &account.password).unwrap();

        if is_valid {
            // Generate a token by encrypting the username with a key and an iv
            // You should use a secure random key and iv in production
            let key = b"0123456789abcdef0123456789abcdef";
            let iv = b"abcdef0123456789abcdef0123456789";
            let token = encrypt(req.username.as_bytes(), key, iv);

            // Return a success response with the token
            return HttpResponse::Ok().json(LoginResponse {
                status: "success".to_string(),
                message: "Login successful".to_string(),
                token: Some(base64::encode(token)),
            });
        }
    }

    // Return an error response if the username or password is incorrect
    HttpResponse::Ok().json(LoginResponse {
        status: "error".to_string(),
        message: "Invalid username or password".to_string(),
        token: None,
    })
}

// Create a new password entry for a site with a username and a password
async fn create_password(
    pool: web::Data<PgPool>,
    req: web::Json<CreatePasswordRequest>,
) -> impl Responder {
    // Decode the token from base64
    let token = match base64::decode(&req.token) {
        Ok(t) => t,
        Err(_) => {
            // Return an error response if the token is invalid
            return HttpResponse::Ok().json(CreatePasswordResponse {
                status: "error".to_string(),
                message: "Invalid token".to_string(),
            });
        }
    };

    // Decrypt the token with the same key and iv used for encryption
    // You should use a secure random key and iv in production
    let key = b"0123456789abcdef0123456789abcdef";
    let iv = b"abcdef0123456789abcdef0123456789";
    let username = match decrypt(&token, key, iv) {
        Ok(u) => String::from_utf8(u).unwrap(),
        Err(_) => {
            // Return an error response if the token is invalid
            return HttpResponse::Ok().json(CreatePasswordResponse {
                status: "error".to_string(),
                message: "Invalid token".to_string(),
            });
        }
    };

    // Get the account id from the database by the username
    let row = sqlx::query!("select id from accounts where username = $1", username)
        .fetch_one(pool.get_ref())
        .await
        .unwrap();

    let account_id = row.id;

    // Encrypt the password with a key and an iv
    // You should use a secure random key and iv in production
    let key = b"fedcba9876543210fedcba9876543210";
    let iv = b"0123456789abcdef0123456789abcdef";
    let encrypted_password = encrypt(req.password.as_bytes(), key, iv);

    // Insert the site, username, and encrypted password into the database
    sqlx::query!("insert into passwords (account_id, site, username, password) values ($1, $2, $3, $4)", account_id, req.site, req.username, encrypted_password)
        .execute(pool.get_ref())
        .await
        .unwrap();

    // Return a success response
    HttpResponse::Ok().json(CreatePasswordResponse {
        status: "success".to_string(),
        message: "Password created".to_string(),
    })
}

// Get all the password entries for the logged in user
async fn get_passwords(
    pool: web::Data<PgPool>,
    req: web::Json<GetPasswordsRequest>,
) -> impl Responder {
    // Decode the token from base64
    let token = match base64::decode(&req.token) {
        Ok(t) => t,
        Err(_) => {
            // Return an error response if the token is invalid
            return HttpResponse::Ok().json(GetPasswordsResponse {
                status: "error".to_string(),
                message: "Invalid token".to_string(),
                passwords: None,
            });
        }
    };

    // Decrypt the token with the same key and iv used for encryption
    // You should use a secure random key and iv in production
    let key = b"0123456789abcdef0123456789abcdef";
    let iv = b"abcdef0123456789abcdef0123456789";
    let username = match decrypt(&token, key, iv) {
        Ok(u) => String::from_utf8(u).unwrap(),
        Err(_) => {
            // Return an error response if the token is invalid
            return HttpResponse::Ok().json(GetPasswordsResponse {
                status: "error".to_string(),
                message: "Invalid token".to_string(),
                passwords: None,
            });
        }
    };

    // Get the account id from the database by the username
    let row = sqlx::query!("select id from accounts where username = $1", username)
        .fetch_one(pool.get_ref())

