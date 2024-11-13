//! Cryptographically secure password generator
//! 
//! This implementation provides a secure password generation utility that:
//! - Uses ChaCha20 CSPRNG for cross-platform cryptographic random generation
//! - Implements rejection sampling to eliminate modulo bias
//! - Enforces configurable minimum requirements for character types
//! - Uses Fisher-Yates shuffle for uniform distribution
//! - Implements secure memory handling practices
//! 
//! original @author Tetsuo
//! reimplemented in rust by @Teach2Breach
//! original publish @date October 25, 2024
//! reimplemented @date November 13, 2024
//! @version 1.0.0
//! 
//! @copyright Copyright Tetsuo (c) 2024 SecurePassGen
//! @license MIT License
//! 
//! MIT License
//! 
//! Copyright (c) 2024 Tetsuo
//! 
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//! 
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//! 
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::env;

const MAX_PASSWORD_LENGTH: usize = 128;
const MIN_PASSWORD_LENGTH: usize = 12;
const ENTROPY_MULTIPLIER: usize = 2;

const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]";

#[derive(Debug)]
struct PasswordRequirements {
    has_upper: bool,
    has_lower: bool,
    has_number: bool,
    has_symbol: bool,
    min_upper: usize,
    min_lower: usize,
    min_number: usize,
    min_symbol: usize,
}

fn get_unbiased_random_char(charset: &str, entropy_pool: &[u8], pool_index: &mut usize) -> Option<char> {
    let charset_size = charset.len();
    let max_valid = u32::MAX - (u32::MAX % charset_size as u32);
    
    if *pool_index + 4 > entropy_pool.len() {
        return None;
    }
    
    let random_value = u32::from_le_bytes(
        entropy_pool[*pool_index..*pool_index + 4].try_into().unwrap()
    );
    *pool_index += 4;
    
    if random_value <= max_valid {
        Some(charset.chars().nth(random_value as usize % charset_size).unwrap())
    } else {
        None
    }
}

fn generate_secure_password(length: usize, req: &PasswordRequirements) -> String {
    if length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH {
        panic!("Invalid password length");
    }

    let min_required = req.min_upper + req.min_lower + req.min_number + req.min_symbol;
    if length < min_required {
        panic!("Password length too short for requirements");
    }

    let mut rng = ChaCha20Rng::from_entropy();
    let mut password = Vec::with_capacity(length);
    
    // Create entropy pool similar to C version
    let pool_size = length * ENTROPY_MULTIPLIER * std::mem::size_of::<u32>();
    let mut entropy_pool = vec![0u8; pool_size];
    let mut pool_index = pool_size;  // Force initial refill

    loop {
        password.clear();
        
        // Refill entropy pool if needed
        if pool_index + 4 > pool_size {
            rng.fill_bytes(&mut entropy_pool);
            pool_index = 0;
        }

        // Add required characters
        for _ in 0..req.min_upper {
            while let None = get_unbiased_random_char(UPPERCASE, &entropy_pool, &mut pool_index) {
                rng.fill_bytes(&mut entropy_pool);
                pool_index = 0;
            }
            password.push(get_unbiased_random_char(UPPERCASE, &entropy_pool, &mut pool_index).unwrap());
        }
        for _ in 0..req.min_lower {
            while let None = get_unbiased_random_char(LOWERCASE, &entropy_pool, &mut pool_index) {
                rng.fill_bytes(&mut entropy_pool);
                pool_index = 0;
            }
            password.push(get_unbiased_random_char(LOWERCASE, &entropy_pool, &mut pool_index).unwrap());
        }
        for _ in 0..req.min_number {
            while let None = get_unbiased_random_char(NUMBERS, &entropy_pool, &mut pool_index) {
                rng.fill_bytes(&mut entropy_pool);
                pool_index = 0;
            }
            password.push(get_unbiased_random_char(NUMBERS, &entropy_pool, &mut pool_index).unwrap());
        }
        for _ in 0..req.min_symbol {
            while let None = get_unbiased_random_char(SYMBOLS, &entropy_pool, &mut pool_index) {
                rng.fill_bytes(&mut entropy_pool);
                pool_index = 0;
            }
            password.push(get_unbiased_random_char(SYMBOLS, &entropy_pool, &mut pool_index).unwrap());
        }

        // Build charset for remaining characters
        let mut charset = String::new();
        if req.has_upper { charset.push_str(UPPERCASE); }
        if req.has_lower { charset.push_str(LOWERCASE); }
        if req.has_number { charset.push_str(NUMBERS); }
        if req.has_symbol { charset.push_str(SYMBOLS); }

        // Fill remaining length
        while password.len() < length {
            while let None = get_unbiased_random_char(&charset, &entropy_pool, &mut pool_index) {
                rng.fill_bytes(&mut entropy_pool);
                pool_index = 0;
            }
            password.push(get_unbiased_random_char(&charset, &entropy_pool, &mut pool_index).unwrap());
        }

        // Secure shuffle using entropy pool for randomness
        let mut shuffle_entropy = vec![0u8; length * std::mem::size_of::<u32>()];
        rng.fill_bytes(&mut shuffle_entropy);
        for i in (1..password.len()).rev() {
            let random_bytes = &shuffle_entropy[i * 4..(i + 1) * 4];
            let random_value = u32::from_le_bytes(random_bytes.try_into().unwrap());
            let j = random_value as usize % (i + 1);
            password.swap(i, j);
        }

        if is_valid_password(&password, req) {
            // Zero out entropy pools before dropping
            entropy_pool.fill(0);
            shuffle_entropy.fill(0);
            return password.into_iter().collect();
        }
    }
}

fn is_valid_password(password: &[char], req: &PasswordRequirements) -> bool {
    let upper_count = password.iter().filter(|&c| UPPERCASE.contains(*c)).count();
    let lower_count = password.iter().filter(|&c| LOWERCASE.contains(*c)).count();
    let number_count = password.iter().filter(|&c| NUMBERS.contains(*c)).count();
    let symbol_count = password.iter().filter(|&c| SYMBOLS.contains(*c)).count();

    upper_count >= req.min_upper && 
    lower_count >= req.min_lower && 
    number_count >= req.min_number && 
    symbol_count >= req.min_symbol
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <password_length>", args[0]);
        std::process::exit(1);
    }

    let length = args[1].parse::<usize>().unwrap_or_else(|_| {
        eprintln!("Invalid password length");
        std::process::exit(1);
    });

    if length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH {
        eprintln!("Password length must be between {} and {}", 
                 MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
        std::process::exit(1);
    }

    let req = PasswordRequirements {
        has_upper: true,
        has_lower: true,
        has_number: true,
        has_symbol: true,
        min_upper: 1,
        min_lower: 1,
        min_number: 1,
        min_symbol: 1,
    };

    let password = generate_secure_password(length, &req);
    println!("Generated Secure Password: {}", password);
}
