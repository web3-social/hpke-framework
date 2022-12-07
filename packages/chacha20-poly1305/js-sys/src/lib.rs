use wasm_bindgen::prelude::*;
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use js_sys::Error;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn chacha20poly1305_seal(key: Box<[u8]>, nonce: Box<[u8]>, aad: Box<[u8]>, pt: Box<[u8]>) -> Result<Vec<u8>, Error> {
    let key = Key::from_slice(key.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce.as_ref());
    let payload = Payload {
        msg: pt.as_ref(),
        aad: aad.as_ref(),
    };
    let ct = cipher.encrypt(nonce, payload).map_err(|_| Error::new("aead error"))?;
    Ok(ct)
}

#[wasm_bindgen]
pub fn chacha20poly1305_open(key: Box<[u8]>, nonce: Box<[u8]>, aad: Box<[u8]>, ct: Box<[u8]>) -> Result<Vec<u8>, Error> {
    let key = Key::from_slice(key.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce.as_ref());
    let payload = Payload {
        msg: ct.as_ref(),
        aad: aad.as_ref(),
    };
    let pt = cipher.decrypt(nonce, payload).map_err(|_| Error::new("aead error"))?;
    Ok(pt)
}

#[wasm_bindgen]
pub fn xchacha20poly1305_seal(key: Box<[u8]>, nonce: Box<[u8]>, aad: Box<[u8]>, pt: Box<[u8]>) -> Result<Vec<u8>, Error> {
    let key = Key::from_slice(key.as_ref());
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce.as_ref());
    let payload = Payload {
        msg: pt.as_ref(),
        aad: aad.as_ref(),
    };
    let ct = cipher.encrypt(nonce, payload).map_err(|_| Error::new("aead error"))?;
    Ok(ct)
}

#[wasm_bindgen]
pub fn xchacha20poly1305_open(key: Box<[u8]>, nonce: Box<[u8]>, aad: Box<[u8]>, ct: Box<[u8]>) -> Result<Vec<u8>, Error> {
    let key = Key::from_slice(key.as_ref());
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce.as_ref());
    let payload = Payload {
        msg: ct.as_ref(),
        aad: aad.as_ref(),
    };
    let pt = cipher.decrypt(nonce, payload).map_err(|_| Error::new("aead error"))?;
    Ok(pt)
}