/**
 * solxact is a utility program that can perform many useful actions on
 * solana transactions.
 *
 * For help on subcommands:
 *
 * solxact help encode        -- for encoding a transaction
 * solxact help decode        -- for decoding a transaction
 * solxact help hash          -- for setting the recent blockhash of a transaction
 * solxact help sign          -- for signing a transaction
 * solxact help show-unsigned -- for showing which signatures are still required
 * solxact help signature     -- for showing a transaction's signature
 * solxact help simulate      -- for simulating a transaction
 * solxact help submit        -- for submitting a transaction
 * solxact help pda           -- for computing program derived addresses
 * solxact help pubkey        -- for displaying pubkeys
 **/
mod transaction;
mod usage;

use bincode::Options;
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::io::BufRead;
use std::io::Write as IoWrite;
use std::str::FromStr;
use transaction::{Address, Instruction, Pubkey, Sha256Digest, Transaction};

const DEFAULT_MAINNET_RPC_URL : &str = "https://api.mainnet-beta.solana.com";
const DEFAULT_TESTNET_RPC_URL : &str = "https://api.testnet.solana.com";
const DEFAULT_DEVNET_RPC_URL : &str = "https://api.devnet.solana.com";
const DEFAULT_LOCALHOST_RPC_URL : &str = "http://localhost:8899";

type Error = Box<dyn std::error::Error>;

#[derive(Debug)]
pub struct StringError
{
    pub msg : String
}

#[derive(Debug)]
enum Encoding
{
    RustBincodeVarInt,

    RustBincodeFixedInt,

    RustBorsh,

    C
}

#[derive(Clone)]
enum DataValue
{
    BoolList(Vec<bool>),

    U8List(Vec<u8>),

    U16List(Vec<u16>),

    U32List(Vec<u32>),

    U64List(Vec<u64>),

    I8List(Vec<i8>),

    I16List(Vec<i16>),

    I32List(Vec<i32>),

    I64List(Vec<i64>),

    F32List(Vec<f32>),

    F64List(Vec<f64>),

    String(String),

    CString
    {
        max_length : u16,
        string : String
    },

    Pubkey(Pubkey),

    Sha256([u8; 32]),

    Pda(Pubkey, Vec<Box<DataValue>>),

    Bump(Pubkey, Vec<Box<DataValue>>),

    PdaNoBump(Pubkey, Vec<Box<DataValue>>),

    Vector(Vec<Box<DataValue>>),

    Struct(Vec<Box<DataValue>>),

    Enum
    {
        index : usize,
        params : Option<Vec<Box<DataValue>>>
    },

    Some(Box<DataValue>),

    None
}

impl std::error::Error for StringError
{
    fn description(&self) -> &str
    {
        &self.msg
    }
}

impl std::fmt::Display for StringError
{
    fn fmt(
        &self,
        f : &mut std::fmt::Formatter
    ) -> std::fmt::Result
    {
        write!(f, "{}", self.msg)
    }
}

fn stre(msg : &str) -> Error
{
    Box::new(StringError { msg : msg.to_string() })
}

fn usage_exit(
    msg : &str,
    error_code : Option<i32>
) -> !
{
    match error_code {
        Some(error_code) => {
            eprintln!("{}", msg);
            std::process::exit(error_code);
        },
        None => {
            println!("{}", msg);
            std::process::exit(0);
        }
    }
}

fn u8_list_to_vec(bytes : &str) -> Result<Vec<u8>, Error>
{
    bytes
        .replace(" ", "")
        .split(",")
        .map(|s| s.parse::<u8>().map_err(|err| stre(&err.to_string())))
        .collect::<Result<Vec<u8>, Error>>()
}

fn make_keypair(s : &str) -> Result<ed25519_dalek::Keypair, Error>
{
    std::fs::read_to_string(s).map_err(|err| stre(&err.to_string())).and_then(|bytes| {
        if bytes.starts_with("[") && bytes.ends_with("]") {
            let bytes = &bytes[1..(bytes.len() - 1)];
            Ok(ed25519_dalek::Keypair::from_bytes(u8_list_to_vec(&bytes)?.as_slice())
                .map_err(|err| stre(&err.to_string()))?)
        }
        else {
            Err(stre(&format!("Invalid key file contents in {}", s)))
        }
    })
}

fn private_key_bytes_array_to_pubkey(bytes : &str) -> Result<Pubkey, Error>
{
    if bytes.starts_with("[") && bytes.ends_with("]") {
        let bytes = &bytes[1..(bytes.len() - 1)];
        Ok(Pubkey(
            ed25519_dalek::Keypair::from_bytes(u8_list_to_vec(&bytes)?.as_slice())
                .map_err(|e| e.to_string())?
                .public
                .to_bytes()
        ))
    }
    else {
        Err(stre(&format!("Invalid private key byte array: {}", bytes)))
    }
}

fn public_key_bytes_array_to_pubkey(bytes : &str) -> Result<Pubkey, Error>
{
    if bytes.starts_with("[") && bytes.ends_with("]") {
        let bytes = &bytes[1..(bytes.len() - 1)];
        Ok(Pubkey(
            u8_list_to_vec(&bytes)?.try_into().map_err(|_| "Incorrect number of bytes in public key".to_string())?
        ))
    }
    else {
        Err(stre(&format!("Invalid public key byte array: {}", bytes)))
    }
}

// Create a pubkey from a string which might represent an actual pubkey in base-58 encoded format, or a filename
// containing an ed25519 keypair, or a JSON byte array of a keypair or pubkey
fn make_pubkey(s : &str) -> Result<Pubkey, Error>
{
    std::fs::read_to_string(&s)
        .map_err(|e| stre(e.to_string().as_str()))
        .and_then(|pk_bytes| private_key_bytes_array_to_pubkey(&pk_bytes))
        .or_else(|_| Pubkey::from_str(&s).map_err(|e| stre(&e)))
        .or_else(|_| private_key_bytes_array_to_pubkey(&s))
        .or_else(|_| public_key_bytes_array_to_pubkey(&s))
}

fn make_sha256(s : &str) -> Result<[u8; 32], Error>
{
    let v = hex::decode(s)?;

    if v.len() == 32 {
        Ok(v.try_into().unwrap())
    }
    else {
        Err(stre(&format!("Invalid sha256: {}", s)))
    }
}

fn bytes_are_curve_point(bytes : &[u8; 32]) -> bool
{
    curve25519_dalek::edwards::CompressedEdwardsY::from_slice(bytes.as_ref()).decompress().is_some()
}

fn try_find_pda(
    pubkey : &Pubkey,
    seed : &[u8],
    bump_seed : Option<u8>
) -> Option<Pubkey>
{
    let mut hasher = Sha256::new();

    hasher.update(&seed);
    if let Some(bump_seed) = bump_seed {
        hasher.update(&[bump_seed]);
    }
    hasher.update(&pubkey.0);
    hasher.update(b"ProgramDerivedAddress");

    let hash = <[u8; 32]>::try_from(hasher.finalize().as_slice()).unwrap();

    if bytes_are_curve_point(&hash) {
        None
    }
    else {
        Some(Pubkey(hash))
    }
}

fn find_pda(
    program_id : &Pubkey,
    seed : &[u8]
) -> Option<(Pubkey, u8)>
{
    // Use the same algorithm as Solana's seed finding algorithm: start the bump seed at 255 and work backwards
    let mut bump_seed = (std::u8::MAX) as i16;

    while bump_seed >= 0 {
        if let Some(pubkey) = try_find_pda(&program_id, seed, Some(bump_seed as u8)) {
            return Some((pubkey, bump_seed as u8));
        }
        bump_seed -= 1;
    }

    None
}

fn skip_comments(words : &mut Vec<String>) -> Result<(), Error>
{
    while (words.len() > 0) && (words[0] == "//") {
        // This is a comment, ignore it
        words.remove(0);
        loop {
            if words.len() == 0 {
                return Err(stre("The final comment is incomplete"));
            }
            else {
                let word = words.remove(0);
                if word == "//" {
                    break;
                }
            }
        }
    }

    Ok(())
}

// Turn words into a pubkey identifier, which is either a single String (being a path, or a Base58-encoded pubkey),
// or is an JSON array (which is turned back into a string)
fn pubkey_from_words(words : &mut Vec<String>) -> Result<String, Error>
{
    if words.len() == 0 {
        Err(stre("Missing pubkey value"))
    }
    else {
        if words[0] == "[" {
            let mut array = "[".to_string();
            words.remove(0);
            loop {
                if words.len() == 0 {
                    return Err(stre("The final pubkey value array is incomplete"));
                }
                let word = words.remove(0);
                array = format!("{}{}", array, word);
                if word == "]" {
                    return Ok(array);
                }
            }
        }
        else {
            Ok(words.remove(0))
        }
    }
}

// encoding is used for pda and pda_nobump accounts
fn read_accounts(
    words : &mut Vec<String>,
    encoding : &Encoding,
    into : &mut Vec<(Address, bool, bool)>
) -> Result<(), Error>
{
    loop {
        skip_comments(words)?;

        if (words.len() == 0) || (words[0] != "account") {
            break;
        }

        words.remove(0);

        if words.len() == 0 {
            return Err(stre("Missing account pubkey"));
        }

        // Account may come from a pda or pda_nobump value
        let pubkey = match words[0].as_str() {
            "pda" | "pda_nobump" => {
                let dv = read_data_value(words)?.unwrap();
                let mut bytes = vec![];
                write_data_value(dv, encoding, &mut bytes)?;
                Pubkey(bytes.as_slice().try_into()?)
            },
            _ => make_pubkey(&pubkey_from_words(words)?)?
        };

        let mut is_signed = false;

        let mut is_write = false;

        if words.len() > 0 {
            match words[0].as_str() {
                "s" => {
                    words.remove(0);
                    is_signed = true;
                },
                "w" => {
                    words.remove(0);
                    is_write = true;
                },
                "sw" | "ws" => {
                    words.remove(0);
                    is_signed = true;
                    is_write = true;
                },
                _ => ()
            }
        }

        into.push((pubkey.into(), is_signed, is_write));
    }

    Ok(())
}

fn is_data_value_terminator(s : &str) -> bool
{
    match s {
        "program" | "bool" | "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64" |
        "string" | "c_string" | "pubkey" | "sha256" | "pda" | "bump" | "pda_nobump" | "vector" | "struct" |
        "enum" | "some" | "none" | "]" | "//" => true,
        _ => false
    }
}

fn read_list<T, F>(
    words : &mut Vec<String>,
    mut f : F
) -> Result<Vec<T>, Error>
where
    F : FnMut(&mut Vec<String>) -> Result<T, Error>
{
    let prefix = words.remove(0);

    let mut ret = vec![];

    loop {
        // Stop at the end or when the next word is one of the value prefixes
        if words.len() == 0 || is_data_value_terminator(&words[0]) {
            break;
        }
        ret.push(f(words)?);
    }

    if ret.len() == 0 {
        Err(stre(&format!("Empty list of values after {}", prefix)))
    }
    else {
        Ok(ret)
    }
}

fn read_single_value(words : &mut Vec<String>) -> Result<String, Error>
{
    // Assume prefix is at first element of vector
    let prefix = words.remove(0);

    if words.len() == 0 {
        return Err(stre(&format!("The final {} parameter is incomplete", prefix)));
    }

    Ok(words.remove(0))
}

fn unescape_string(s : &str) -> String
{
    s.replace("\\\"", "\"").replace("\\\\", "\\")
}

fn read_string_value(words : &mut Vec<String>) -> Result<String, Error>
{
    if words.len() == 0 {
        return Err(stre("The final string parameter is incomplete"));
    }

    let word = words.remove(0);

    if word.starts_with("\"") {
        if word.ends_with("\"") {
            Ok(unescape_string(&word))
        }
        else {
            let mut ret = String::new();

            write!(ret, "{}", unescape_string(&word[1..]))?;

            loop {
                if words.len() == 0 {
                    return Err(stre("The final string parameter is incomplete"));
                }

                let word = words.remove(0);

                if word.ends_with("\"") {
                    write!(ret, "{}", unescape_string(&word[0..(word.len() - 1)]))?;
                    return Ok(ret);
                }
                else {
                    write!(ret, "{}", unescape_string(&word))?;
                }
            }
        }
    }
    else {
        Ok(word)
    }
}

fn read_vector(
    prefix : &str,
    words : &mut Vec<String>
) -> Result<Vec<Box<DataValue>>, Error>
{
    if words.len() == 0 {
        return Err(stre(&format!("The final {} parameter is incomplete", prefix)));
    }

    let word = words.remove(0);

    if word != "[" {
        return Err(stre(&format!("Expected [ after {}", prefix)));
    }

    let mut v = vec![];

    loop {
        skip_comments(words)?;

        if words.len() == 0 {
            return Err(stre(&format!("The final {} parameter is incomplete", prefix)));
        }

        if words[0] == "]" {
            words.remove(0);
            break;
        }

        if let Some(dv) = read_data_value(words)? {
            v.push(Box::new(dv));
        }
        else {
            break;
        }
    }

    if v.len() == 0 {
        Err(stre(&format!("Empty {}", prefix)))
    }
    else {
        Ok(v)
    }
}

fn read_data_value(words : &mut Vec<String>) -> Result<Option<DataValue>, Error>
{
    match words[0].as_str() {
        "bool" => Ok(Some(DataValue::BoolList(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(bool::from_str(&word).map_err(|_| stre(&format!("Invalid bool value: {}", word)))?)
        })?))),
        "u8" => Ok(Some(DataValue::U8List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(u8::from_str(&word).map_err(|_| stre(&format!("Invalid u8 value: {}", word)))?)
        })?))),
        "u16" => Ok(Some(DataValue::U16List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(u16::from_str(&word).map_err(|_| stre(&format!("Invalid u16 value: {}", word)))?)
        })?))),
        "u32" => Ok(Some(DataValue::U32List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(u32::from_str(&word).map_err(|_| stre(&format!("Invalid u32 value: {}", word)))?)
        })?))),
        "u64" => Ok(Some(DataValue::U64List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(u64::from_str(&word).map_err(|_| stre(&format!("Invalid u64 value: {}", word)))?)
        })?))),
        "i8" => Ok(Some(DataValue::I8List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(i8::from_str(&word).map_err(|_| stre(&format!("Invalid i8 value: {}", word)))?)
        })?))),
        "i16" => Ok(Some(DataValue::I16List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(i16::from_str(&word).map_err(|_| stre(&format!("Invalid i16 value: {}", word)))?)
        })?))),
        "i32" => Ok(Some(DataValue::I32List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(i32::from_str(&word).map_err(|_| stre(&format!("Invalid i32 value: {}", word)))?)
        })?))),
        "i64" => Ok(Some(DataValue::I64List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(i64::from_str(&word).map_err(|_| stre(&format!("Invalid i64 value: {}", word)))?)
        })?))),
        "f32" => Ok(Some(DataValue::F32List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(f32::from_str(&word).map_err(|_| stre(&format!("Invalid f32 value: {}", word)))?)
        })?))),
        "f64" => Ok(Some(DataValue::F64List(read_list(words, |ws| {
            let word = ws.remove(0);
            Ok(f64::from_str(&word).map_err(|_| stre(&format!("Invalid f64 value: {}", word)))?)
        })?))),
        "string" => {
            words.remove(0); // string
            Ok(Some(DataValue::String(read_string_value(words)?)))
        },
        "c_string" => {
            words.remove(0); // c_string
            if words.len() == 0 {
                return Err(stre(&format!("The final c_string parameter is incomplete")));
            }
            let word = words.remove(0);
            let max_length =
                u16::from_str(&word).map_err(|_| stre(&format!("Invalid max_length in c_string value: {}", word)))?;
            Ok(Some(DataValue::CString { max_length, string : read_string_value(words)? }))
        },
        "pubkey" => {
            words.remove(0);
            Ok(Some(DataValue::Pubkey(make_pubkey(&pubkey_from_words(words)?)?)))
        },
        "sha256" => Ok(Some(DataValue::Sha256(make_sha256(&read_single_value(words)?)?))),
        "pda" => {
            words.remove(0);
            Ok(Some(DataValue::Pda(make_pubkey(&pubkey_from_words(words)?)?, read_vector("pda", words)?)))
        },
        "bump" => {
            words.remove(0);
            Ok(Some(DataValue::Bump(make_pubkey(&pubkey_from_words(words)?)?, read_vector("bump", words)?)))
        },
        "pda_nobump" => {
            words.remove(0);
            Ok(Some(DataValue::PdaNoBump(make_pubkey(&pubkey_from_words(words)?)?, read_vector("pda_nobump", words)?)))
        },
        "vector" => {
            words.remove(0); // vector
            if words.len() == 0 {
                return Err(stre("The final vector parameter is incomplete"));
            }
            Ok(Some(DataValue::Vector(read_vector("vector", words)?)))
        },
        "struct" => {
            words.remove(0); // struct
            if words.len() == 0 {
                return Err(stre("The final struct parameter is incomplete"));
            }
            Ok(Some(DataValue::Struct(read_vector("struct", words)?)))
        },
        "enum" => {
            words.remove(0); // enum
            if words.len() == 0 {
                return Err(stre("The final enum parameter is incomplete"));
            }
            let index = words.remove(0);
            let index =
                usize::from_str(&index).map_err(|err| stre(&format!("Invalid enum index {}: {}", index, err)))?;
            Ok(Some(DataValue::Enum {
                index,
                params : {
                    if (words.len() == 0) || (words[0] != "[") {
                        None
                    }
                    else {
                        Some(read_vector("enum", words)?)
                    }
                }
            }))
        },
        "some" => {
            words.remove(0); // some
            Ok(Some(DataValue::Some(Box::new(
                read_data_value(words)?.ok_or_else(|| stre("The final some parameter is incomplete"))?
            ))))
        },
        "none" => Ok(Some(DataValue::None)),
        "program" => Ok(None),
        _ => Err(stre(&format!("Invalid data: {}", words[0])))
    }
}

fn read_data_values(
    words : &mut Vec<String>,
    into : &mut Vec<DataValue>
) -> Result<(), Error>
{
    loop {
        skip_comments(words)?;

        if words.len() == 0 {
            break;
        }

        let data_value = read_data_value(words)?;

        if let Some(data_value) = data_value {
            into.push(data_value);
        }
        else {
            break;
        }
    }

    Ok(())
}

fn vector_normalize(v : &Vec<Box<DataValue>>) -> Vec<Box<DataValue>>
{
    if v.len() == 1 {
        match &*v[0] {
            DataValue::U8List(v) => v.iter().map(|e| Box::new(DataValue::U8List(vec![*e]))).collect(),
            DataValue::U16List(v) => v.iter().map(|e| Box::new(DataValue::U16List(vec![*e]))).collect(),
            DataValue::U32List(v) => v.iter().map(|e| Box::new(DataValue::U32List(vec![*e]))).collect(),
            DataValue::U64List(v) => v.iter().map(|e| Box::new(DataValue::U64List(vec![*e]))).collect(),
            DataValue::I8List(v) => v.iter().map(|e| Box::new(DataValue::I8List(vec![*e]))).collect(),
            DataValue::I16List(v) => v.iter().map(|e| Box::new(DataValue::I16List(vec![*e]))).collect(),
            DataValue::I32List(v) => v.iter().map(|e| Box::new(DataValue::I32List(vec![*e]))).collect(),
            DataValue::I64List(v) => v.iter().map(|e| Box::new(DataValue::I64List(vec![*e]))).collect(),
            DataValue::F32List(v) => v.iter().map(|e| Box::new(DataValue::F32List(vec![*e]))).collect(),
            DataValue::F64List(v) => v.iter().map(|e| Box::new(DataValue::F64List(vec![*e]))).collect(),
            _ => v.clone()
        }
    }
    else {
        v.clone()
    }
}

fn bincode_encode<T : serde::ser::Serialize>(
    v : T,
    varint : bool,
    w : &mut dyn std::io::Write
) -> Result<(), Error>
where
{
    if varint {
        bincode::DefaultOptions::new().with_varint_encoding().serialize_into(w, &v).map_err(|e| e.into())
    }
    else {
        bincode::DefaultOptions::new().with_fixint_encoding().serialize_into(w, &v).map_err(|e| e.into())
    }
}

fn write_rust_bincode_value(
    data_value : DataValue,
    varint : bool,
    into : &mut Vec<u8>
) -> Result<(), Error>
{
    match data_value {
        DataValue::BoolList(v) => {
            for u in v.into_iter() {
                bincode_encode(u, varint, into)?;
            }
            Ok(())
        },

        DataValue::U8List(v) => {
            for u in v.into_iter() {
                bincode_encode(u, varint, into)?;
            }
            Ok(())
        },

        DataValue::U16List(v) => {
            for u in v.into_iter() {
                bincode_encode(u, varint, into)?;
            }
            Ok(())
        },

        DataValue::U32List(v) => {
            for u in v.into_iter() {
                bincode_encode(u, varint, into)?;
            }
            Ok(())
        },

        DataValue::U64List(v) => {
            for u in v.into_iter() {
                bincode_encode(u, varint, into)?;
            }
            Ok(())
        },

        DataValue::I8List(v) => {
            for i in v.into_iter() {
                bincode_encode(i, varint, into)?;
            }
            Ok(())
        },

        DataValue::I16List(v) => {
            for i in v.into_iter() {
                bincode_encode(i, varint, into)?;
            }
            Ok(())
        },

        DataValue::I32List(v) => {
            for i in v.into_iter() {
                bincode_encode(i, varint, into)?;
            }
            Ok(())
        },

        DataValue::I64List(v) => {
            for i in v.into_iter() {
                bincode_encode(i, varint, into)?;
            }
            Ok(())
        },

        DataValue::F32List(v) => {
            for f in v.into_iter() {
                bincode_encode(f, varint, into)?;
            }
            Ok(())
        },

        DataValue::F64List(v) => {
            for f in v.into_iter() {
                bincode_encode(f, varint, into)?;
            }
            Ok(())
        },

        DataValue::String(s) => bincode_encode(s, varint, into),

        DataValue::CString { max_length, string } => {
            let zeroes = (max_length as usize).checked_sub(string.len()).ok_or_else(|| {
                stre(&format!("c_string {} has length greater than max_length {}", string.len(), max_length))
            })?;
            into.extend(string.as_bytes());
            for _ in 0..zeroes {
                into.push(0);
            }
            Ok(())
        },

        DataValue::Pubkey(p) => bincode_encode(p.0, varint, into),

        DataValue::Sha256(a) => {
            for u in a {
                bincode_encode(u, varint, into)?;
            }
            Ok(())
        },

        DataValue::Pda(program_id, v) => {
            // Encode v into a vector of bytes, which is the base seed.  Fixed int is used as varint doesn't
            // make sense for seed values.
            let mut seed = vec![];
            write_rust_bincode_value(DataValue::Vector(v), false, &mut seed)?;
            // Compute the address and bump seed, which must succeed since a
            // bump seed is being used
            let (pubkey, _) = find_pda(&program_id, &seed).unwrap();
            // Encode the pubkey
            bincode_encode(pubkey.0, false, into)
        },

        DataValue::Bump(program_id, v) => {
            // Encode v into a vector of bytes, which is the base seed.  Fixed int is used as varint doesn't
            // make sense for seed values.
            let mut seed = vec![];
            write_rust_bincode_value(DataValue::Vector(v), false, &mut seed)?;
            // Compute the address and bump seed, which must succeed since a
            // bump seed is being used
            let (_, bump_seed) = find_pda(&program_id, &seed).unwrap();
            // Encode the pubkey.
            bincode_encode(bump_seed, varint, into)
        },

        DataValue::PdaNoBump(program_id, v) => {
            // Encode v into a vector of bytes, which is the base seed.  Fixed int is used as varint doesn't
            // make sense for seed values.
            let mut seed = vec![];
            write_rust_bincode_value(DataValue::Vector(v), false, &mut seed)?;
            // Compute the address and bump seed, which may fail since a bump seed is not being used
            match try_find_pda(&program_id, &seed, None) {
                Some(pubkey) => {
                    // Encode the pubkey
                    bincode_encode(pubkey.0, false, into)
                },
                None => Err(stre("PDA could not be derived"))
            }
        },

        DataValue::Vector(v) => {
            let v = vector_normalize(&v);
            bincode_encode(v.len(), varint, into)?;
            for v in v.into_iter() {
                write_rust_bincode_value(*v, varint, into)?;
            }
            Ok(())
        },

        DataValue::Struct(v) => {
            for v in v.into_iter() {
                write_rust_bincode_value(*v, varint, into)?;
            }
            Ok(())
        },

        DataValue::Enum { index, params } => {
            if index > (u32::MAX as usize) {
                return Err(stre(&format!(
                    "enum index {} is greater than max of {} supported by borsh encoding",
                    index,
                    u32::MAX
                )));
            }
            bincode_encode(index as u32, varint, into)?;
            if let Some(params) = params {
                write_rust_bincode_value(DataValue::Struct(params), varint, into)
            }
            else {
                Ok(())
            }
        },

        DataValue::Some(v) => {
            write_rust_bincode_value(DataValue::Enum { index : 1, params : Some(vec![v]) }, varint, into)
        },

        DataValue::None => write_rust_bincode_value(DataValue::Enum { index : 0, params : None }, varint, into)
    }
}

fn borsh_encode<T : borsh::BorshSerialize>(
    v : T,
    w : &mut dyn std::io::Write
) -> Result<(), Error>
{
    borsh::to_writer(w, &v).map_err(|e| e.into())
}

fn write_rust_borsh_value(
    data_value : DataValue,
    into : &mut Vec<u8>
) -> Result<(), Error>
{
    match data_value {
        DataValue::BoolList(v) => {
            for u in v.into_iter() {
                borsh_encode(u, into)?;
            }
            Ok(())
        },

        DataValue::U8List(v) => {
            for u in v.into_iter() {
                borsh_encode(u, into)?;
            }
            Ok(())
        },

        DataValue::U16List(v) => {
            for u in v.into_iter() {
                borsh_encode(u, into)?;
            }
            Ok(())
        },

        DataValue::U32List(v) => {
            for u in v.into_iter() {
                borsh_encode(u, into)?;
            }
            Ok(())
        },

        DataValue::U64List(v) => {
            for u in v.into_iter() {
                borsh_encode(u, into)?;
            }
            Ok(())
        },

        DataValue::I8List(v) => {
            for i in v.into_iter() {
                borsh_encode(i, into)?;
            }
            Ok(())
        },

        DataValue::I16List(v) => {
            for i in v.into_iter() {
                borsh_encode(i, into)?;
            }
            Ok(())
        },

        DataValue::I32List(v) => {
            for i in v.into_iter() {
                borsh_encode(i, into)?;
            }
            Ok(())
        },

        DataValue::I64List(v) => {
            for i in v.into_iter() {
                borsh_encode(i, into)?;
            }
            Ok(())
        },

        DataValue::F32List(v) => {
            for f in v.into_iter() {
                borsh_encode(f, into)?;
            }
            Ok(())
        },

        DataValue::F64List(v) => {
            for f in v.into_iter() {
                borsh_encode(f, into)?;
            }
            Ok(())
        },

        DataValue::String(s) => borsh_encode(s, into),

        DataValue::CString { max_length, string } => {
            let zeroes = (max_length as usize).checked_sub(string.len()).ok_or_else(|| {
                stre(&format!("c_string {} has length greater than max_length {}", string.len(), max_length))
            })?;
            into.extend(string.as_bytes());
            for _ in 0..zeroes {
                into.push(0);
            }
            Ok(())
        },

        DataValue::Pubkey(p) => borsh_encode(p.0, into),

        DataValue::Sha256(a) => {
            for u in a {
                borsh_encode(u, into)?;
            }
            Ok(())
        },

        DataValue::Pda(program_id, v) => {
            // Encode v into a vector of bytes, which is the base seed
            let mut seed = vec![];
            write_rust_borsh_value(DataValue::Vector(v), &mut seed)?;
            // Compute the address and bump seed, which must succeed since a
            // bump seed is being used
            let (pubkey, _) = find_pda(&program_id, &seed).unwrap();
            // Encode the pubkey
            borsh_encode(pubkey.0, into)
        },

        DataValue::Bump(program_id, v) => {
            // Encode v into a vector of bytes, which is the base seed
            let mut seed = vec![];
            write_rust_borsh_value(DataValue::Vector(v), &mut seed)?;
            // Compute the address and bump seed, which must succeed since a
            // bump seed is being used
            let (_, bump_seed) = find_pda(&program_id, &seed).unwrap();
            // Encode the pubkey
            borsh_encode(bump_seed, into)
        },

        DataValue::PdaNoBump(program_id, v) => {
            // Encode v into a vector of bytes, which is the base seed
            let mut seed = vec![];
            write_rust_borsh_value(DataValue::Vector(v), &mut seed)?;
            // Compute the address and bump seed, which may fail since a bump seed is not being used
            match try_find_pda(&program_id, &seed, None) {
                Some(pubkey) => {
                    // Encode the pubkey
                    borsh_encode(pubkey.0, into)
                },
                None => Err(stre("PDA could not be derived"))
            }
        },

        DataValue::Vector(v) => {
            let v = vector_normalize(&v);
            if v.len() > (u32::MAX as usize) {
                return Err(stre(&format!(
                    "vector length {} is greater than max of {} supported by borsh encoding",
                    v.len(),
                    u32::MAX
                )));
            }
            borsh_encode(v.len() as u32, into)?;
            for v in v.into_iter() {
                write_rust_borsh_value(*v, into)?;
            }
            Ok(())
        },

        DataValue::Struct(v) => {
            for v in v.into_iter() {
                write_rust_borsh_value(*v, into)?;
            }
            Ok(())
        },

        DataValue::Enum { index, params } => {
            if index > (u8::MAX as usize) {
                return Err(stre(&format!(
                    "enum index {} is greater than max of {} supported by borsh encoding",
                    index,
                    u8::MAX
                )));
            }
            borsh_encode(index as u8, into)?;
            if let Some(params) = params {
                write_rust_borsh_value(DataValue::Struct(params), into)
            }
            else {
                Ok(())
            }
        },

        DataValue::Some(v) => write_rust_borsh_value(DataValue::Enum { index : 1, params : Some(vec![v]) }, into),

        DataValue::None => write_rust_borsh_value(DataValue::Enum { index : 0, params : None }, into)
    }
}

fn c_align(
    alignment : usize,
    should_align : bool,
    into : &mut Vec<u8>
)
{
    if should_align {
        while (into.len() % alignment) != 0 {
            into.push(0);
        }
    }
}

fn c_alignment(dv : &DataValue) -> usize
{
    match dv {
        DataValue::BoolList(_) => 1,
        DataValue::U8List(_) => 1,
        DataValue::U16List(_) => 2,
        DataValue::U32List(_) => 4,
        DataValue::U64List(_) => 8,
        DataValue::I8List(_) => 1,
        DataValue::I16List(_) => 2,
        DataValue::I32List(_) => 4,
        DataValue::I64List(_) => 8,
        DataValue::F32List(_) => 4,
        DataValue::F64List(_) => 8,
        DataValue::String(_) => 1,
        DataValue::CString { max_length: _, string: _ } => 1,
        DataValue::Pubkey(_) => 1,
        DataValue::Sha256(_) => 1,
        DataValue::Pda(_, _) => 1,
        DataValue::Bump(_, _) => 1,
        DataValue::PdaNoBump(_, _) => 1,
        DataValue::Vector(_) => 1,
        DataValue::Struct(v) => c_max_alignment(v),
        DataValue::Enum { index: _, params } => {
            if let Some(p) = params {
                c_max_alignment(&p)
            }
            else {
                0
            }
        },
        DataValue::Some(v) => c_alignment(v),
        DataValue::None => 1
    }
}

fn c_max_alignment(v : &Vec<Box<DataValue>>) -> usize
{
    let mut max = 1;

    for dv in v {
        let alignment = c_alignment(dv);
        if alignment > max {
            max = alignment;
        }
    }

    max
}

fn write_c_value(
    data_value : DataValue,
    align : bool,
    into : &mut Vec<u8>
) -> Result<(), Error>
{
    match data_value {
        DataValue::BoolList(v) => v.into_iter().for_each(|b| {
            into.push(if b { 1 } else { 0 });
        }),

        DataValue::U8List(mut v) => {
            into.append(&mut v);
        },

        DataValue::U16List(v) => v.into_iter().for_each(|u| {
            c_align(2, align, into);
            into.extend(u.to_le_bytes());
        }),

        DataValue::U32List(v) => v.into_iter().for_each(|u| {
            c_align(4, align, into);
            into.extend(u.to_le_bytes());
        }),

        DataValue::U64List(v) => v.into_iter().for_each(|u| {
            c_align(8, align, into);
            into.extend(u.to_le_bytes());
        }),

        DataValue::I8List(v) => v.into_iter().for_each(|i| {
            into.extend(i.to_le_bytes());
        }),

        DataValue::I16List(v) => v.into_iter().for_each(|i| {
            c_align(2, align, into);
            into.extend(i.to_le_bytes());
        }),

        DataValue::I32List(v) => v.into_iter().for_each(|i| {
            c_align(4, align, into);
            into.extend(i.to_le_bytes());
        }),

        DataValue::I64List(v) => v.into_iter().for_each(|i| {
            c_align(8, align, into);
            into.extend(i.to_le_bytes());
        }),

        DataValue::F32List(v) => v.into_iter().for_each(|f| {
            c_align(4, align, into);
            into.extend(f.to_le_bytes());
        }),

        DataValue::F64List(v) => v.into_iter().for_each(|f| {
            c_align(8, align, into);
            into.extend(f.to_le_bytes());
        }),

        DataValue::String(s) => into.extend(s.as_bytes()),

        DataValue::CString { max_length, string } => {
            let zeroes = (max_length as usize).checked_sub(string.len()).ok_or_else(|| {
                stre(&format!("c_string {} has length greater than max_length {}", string.len(), max_length))
            })?;
            into.extend(string.as_bytes());
            for _ in 0..zeroes {
                into.push(0);
            }
        },

        DataValue::Pubkey(p) => write_c_value(DataValue::U8List(p.0.into()), align, into)?,

        DataValue::Sha256(p) => write_c_value(DataValue::U8List(p.into()), align, into)?,

        DataValue::Pda(program_id, v) => {
            // Encode v into a vector of data values.  No alignment is used since seeds should be directly
            // concatenated.
            let mut seed = vec![];
            for dv in v.into_iter() {
                write_c_value(*dv, false, &mut seed)?;
            }
            // Compute the address and bump seed, which must succeed since a
            // bump seed is being used
            let (pubkey, _) = find_pda(&program_id, &seed).unwrap();
            // Encode the pubkey
            write_c_value(DataValue::Pubkey(pubkey), false, into)?
        },

        DataValue::Bump(program_id, v) => {
            // Encode v into a vector of data values.  No alignment is used since seeds should be directly
            // concatenated.
            let mut seed = vec![];
            for dv in v.into_iter() {
                write_c_value(*dv, false, &mut seed)?;
            }
            // Compute the address and bump seed, which must succeed since a
            // bump seed is being used
            let (_, bump_seed) = find_pda(&program_id, &seed).unwrap();
            // Encode the pubkey
            into.extend(bump_seed.to_le_bytes())
        },

        DataValue::PdaNoBump(program_id, v) => {
            // Encode v into a vector of data values.  No alignment is used since seeds should be directly
            // concatenated.
            let mut seed = vec![];
            for dv in v.into_iter() {
                write_c_value(*dv, false, &mut seed)?;
            }
            // Compute the address and bump seed, which may fail since a bump seed is not being used
            match try_find_pda(&program_id, &seed, None) {
                Some(pubkey) => {
                    // Encode the pubkey
                    write_c_value(DataValue::Pubkey(pubkey), false, into)?
                },
                None => return Err(stre("PDA could not be derived"))
            }
        },

        DataValue::Vector(_) => return Err(stre("vector value cannot be used with c encoding")),

        DataValue::Struct(v) => {
            let alignment = c_max_alignment(&v);
            c_align(alignment, align, into);
            for v in v.into_iter() {
                write_c_value(*v, align, into)?;
            }
            c_align(alignment, align, into);
        },

        DataValue::Enum { index, params } => {
            if index > (u8::MAX as usize) {
                return Err(stre(&format!(
                    "enum index {} is greater than max of {} supported by c encoding",
                    index,
                    u8::MAX
                )));
            }
            into.push(index as u8);
            if let Some(params) = params {
                write_c_value(DataValue::Struct(params), align, into)?
            }
        },

        DataValue::Some(v) => write_c_value(DataValue::Enum { index : 1, params : Some(vec![v]) }, align, into)?,

        DataValue::None => write_c_value(DataValue::Enum { index : 0, params : None }, align, into)?
    }

    Ok(())
}

fn write_data_value(
    data_value : DataValue,
    encoding : &Encoding,
    into : &mut Vec<u8>
) -> Result<(), Error>
{
    match encoding {
        Encoding::RustBincodeVarInt => write_rust_bincode_value(data_value, true, into),
        Encoding::RustBincodeFixedInt => write_rust_bincode_value(data_value, false, into),
        Encoding::RustBorsh => write_rust_borsh_value(data_value, into),
        Encoding::C => write_c_value(data_value, true, into)
    }
}

fn split_proper(
    mut w : &str,
    delim : char
) -> Vec<&str>
{
    let mut ret = vec![];

    loop {
        if let Some(index) = w.find(delim) {
            if index > 0 {
                ret.push(&w[0..index]);
            }
            ret.push(&w[index..(index + 1)]);
            w = &w[(index + 1)..];
        }
        else {
            if w.len() > 0 {
                ret.push(&w);
            }
            break;
        }
    }

    ret
}

fn make_words(w : &str) -> Vec<String>
{
    split_proper(w, '[')
        .iter()
        .map(|s| split_proper(s, ']'))
        .flatten()
        .collect::<Vec<&str>>()
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
}

fn do_encode(args : &mut std::env::Args) -> Result<(), Error>
{
    // If args is empty, then read from stdin
    let args : Vec<String> = args.collect();

    let mut words = Vec::<String>::new();

    if args.len() == 0 {
        // Read args from stdin.  Split all [ and ] off into separate word to make parsing easier
        for line in std::io::BufReader::new(std::io::stdin()).lines() {
            line?.split_whitespace().for_each(|e| {
                words.extend(make_words(e));
            });
        }
    }
    else {
        args.iter().for_each(|a| words.extend(make_words(&a)));
    }

    // If first element is encoding, then set the encoding from it; else use a default
    if words.len() == 0 {
        return Err(stre("No encode parameters"));
    }

    let encoding = {
        if words[0] == "encoding" {
            let encoding = read_single_value(&mut words)?;
            match encoding.as_str() {
                "rust_bincode_varint" => Encoding::RustBincodeVarInt,
                "rust_bincode_fixedint" => Encoding::RustBincodeFixedInt,
                "rust_borsh" => Encoding::RustBorsh,
                "c" => Encoding::C,
                _ => return Err(stre(&format!("Invalid encoding: {}", encoding)))
            }
        }
        else {
            Encoding::RustBincodeVarInt
        }
    };

    // Read fee payer
    let fee_payer = {
        if words.len() == 0 {
            return Err(stre("Missing fee payer"));
        }

        if words[0] != "fee_payer" {
            return Err(stre("Expected fee_payer before instructions"));
        }

        words.remove(0);

        make_pubkey(&pubkey_from_words(&mut words)?)?
    };

    let mut transaction = Transaction::new(fee_payer);

    // Read and add instructions
    loop {
        skip_comments(&mut words)?;

        if words.len() == 0 {
            break;
        }

        if words[0] != "program" {
            return Err(stre("First line of instruction is expected to be program"));
        }

        words.remove(0);

        let program_id = make_pubkey(&pubkey_from_words(&mut words)?)?;

        let mut accounts : Vec<(Address, bool, bool)> = vec![];

        read_accounts(&mut words, &encoding, &mut accounts)?;

        let mut data_values = Vec::<DataValue>::new();

        read_data_values(&mut words, &mut data_values)?;

        let mut data = Vec::<u8>::new();

        for dv in data_values.into_iter() {
            write_data_value(dv, &encoding, &mut data)?;
        }

        transaction.add_instruction(Instruction { program_address : program_id.into(), addresses : accounts, data });
    }

    transaction.encode(&mut std::io::stdout())
}

fn do_decode() -> Result<(), Error>
{
    write!(std::io::stdout(), "{}", format!("{}", Transaction::decode(&mut std::io::stdin())?))
        .map_err(|err| Box::new(err).into())
}

fn post_json_honor_backoff(
    url : &str,
    json : &str
) -> Result<ureq::Response, ureq::Error>
{
    loop {
        match ureq::post(&url).set("Content-Type", "application/json").send_string(&json) {
            Ok(response) => return Ok(response),
            Err(ureq::Error::Status(status, response)) => {
                if status == 429 {
                    // Sleep according to the Retry-After header, or a default of 3 seconds if that header is not
                    // present
                    std::thread::sleep(std::time::Duration::from_secs(
                        response.header("Retry-After").and_then(|value| value.parse::<u64>().ok()).unwrap_or(3)
                    ));
                }
                else {
                    return Err(ureq::Error::Status(status, response));
                }
            },
            Err(error) => return Err(error)
        }
    }
}

fn fetch_recent_blockhash_using_method(
    rpc_url : &str,
    method : &str
) -> Result<String, Error>
{
    let resp = post_json_honor_backoff(
        rpc_url,
        &format!(
            "{}",
            serde_json::json!({
                "jsonrpc" : "2.0",
                "id" : 1,
                "method" : method
            })
        )
    )?;

    match jv(serde_json::from_reader(resp.into_reader()).map_err(|e| format!("{}", e))?, "result.value.blockhash")? {
        serde_json::Value::String(s) => Ok(s),
        _ => Err(stre(&format!("Invalid response to {}", method)))
    }
}

fn fetch_recent_blockhash(rpc_url : String) -> Result<String, Error>
{
    fetch_recent_blockhash_using_method(&rpc_url, "getLatestBlockhash")
        .or_else(|_| fetch_recent_blockhash_using_method(&rpc_url, "getRecentBlockhash"))
}

fn jv(
    mut v : serde_json::Value,
    path : &str
) -> Result<serde_json::Value, Error>
{
    for s in path.split(".") {
        v = match v {
            serde_json::Value::Object(m) => {
                m.get(s).ok_or(format!("Invalid response json, missing field {}", s))?.clone()
            },
            _ => return Err(stre("Invalid response json, expected object"))
        };
    }

    Ok(v)
}

fn get_rpc_url(args : &mut std::env::Args) -> Result<String, Error>
{
    let args : Vec<String> = args.collect();

    Ok(match args.len() {
        0 => DEFAULT_MAINNET_RPC_URL.to_string(),
        1 => match args[0].as_str() {
            "l" | "localhost" => DEFAULT_LOCALHOST_RPC_URL.to_string(),
            "d" | "devnet" => DEFAULT_DEVNET_RPC_URL.to_string(),
            "t" | "testnet" => DEFAULT_TESTNET_RPC_URL.to_string(),
            "m" | "mainnet" => DEFAULT_MAINNET_RPC_URL.to_string(),
            _ => args[0].clone()
        },
        _ => return Err(stre(&format!("Invalid argument: {}", args[1])))
    })
}

fn do_hash(args : &mut std::env::Args) -> Result<(), Error>
{
    let mut transaction = Transaction::decode(&mut std::io::stdin())?;

    transaction.set_recent_blockhash(Sha256Digest::from_str(&fetch_recent_blockhash(get_rpc_url(args)?)?)?);

    transaction.encode(&mut std::io::stdout())
}

fn do_show_unsigned() -> Result<(), Error>
{
    Ok(Transaction::decode(&mut std::io::stdin())?.needed_signatures().for_each(|p| println!("{}", p)))
}

fn do_signature() -> Result<(), Error>
{
    let tx = Transaction::decode(&mut std::io::stdin())?;

    if tx.signed_read_write_addresses.len() > 0 {
        if let Some(signature) = tx.signed_read_write_addresses[0].signature {
            println!("{}", bs58::encode(signature.to_bytes()).into_string());
            return Ok(());
        }
    }

    Err(stre("Transaction is not signed and thus has no signature"))
}

fn do_sign(args : &mut std::env::Args) -> Result<(), Error>
{
    let mut keypairs = vec![];

    for a in args {
        keypairs.push(make_keypair(&a)?);
    }

    let mut transaction = Transaction::decode(&mut std::io::stdin())?;

    let mut message = vec![];

    transaction.message(&mut message)?;

    for keypair in keypairs {
        transaction.sign(&Pubkey(keypair.public.to_bytes()), keypair.sign(&message))?;
    }

    transaction.encode(&mut std::io::stdout())
}

fn do_simulate(args : &mut std::env::Args) -> Result<(), Error>
{
    let rpc_url = get_rpc_url(args)?;

    let transaction = {
        let decoded_transaction = Transaction::decode(&mut std::io::stdin())?;
        let mut encoded_transaction = vec![];
        decoded_transaction.encode(&mut encoded_transaction)?;
        encoded_transaction
    };

    let json_request = format!(
        "{}",
        serde_json::json!({
        "jsonrpc" : "2.0",
        "id" : 1,
        "method" : "simulateTransaction",
        "params" : [
            base64::encode(&transaction),
            {
                "encoding" : "base64"
            }
        ]
        })
    );

    let resp = post_json_honor_backoff(&rpc_url, &json_request).map_err(|e| format!("{}", e))?;

    let result_json = serde_json::from_reader(resp.into_reader()).map_err(|e| format!("{}", e))?;

    let result_json_string = format!("{}", result_json);

    match jv(result_json, "result.value.err") {
        Ok(serde_json::Value::Null) => {
            std::io::stdout()
                .write(&transaction)
                .map_err(|e| format!("Failed to write transaction to stdout: {}", e))?;
            Ok(())
        },
        Ok(v) => Err(stre(&format!("{}", v))),
        Err(_) => Err(stre(&result_json_string))
    }
}

fn do_submit(args : &mut std::env::Args) -> Result<(), Error>
{
    let rpc_url = get_rpc_url(args)?;

    let transaction = Transaction::decode(&mut std::io::stdin())?;

    // Sanity check transaction to make sure that it has all needed signatures
    let mut needed_signatures = transaction.needed_signatures();

    let needed_signature = needed_signatures.next();

    if let Some(needed_signature) = needed_signature {
        let mut msg = "Transaction cannot be submitted because it is not signed by: ".to_string();

        write!(msg, "{}", needed_signature)?;

        for pubkey in needed_signatures {
            write!(msg, ", {}", pubkey)?;
        }

        return Err(stre(&msg));
    }

    let mut encoded_transaction = vec![];

    transaction.encode(&mut encoded_transaction)?;

    let json_request = format!(
        "{}",
        serde_json::json!({
            "jsonrpc" : "2.0",
            "id" : 1,
            "method" : "sendTransaction",
            "params" : [
                base64::encode(&encoded_transaction),
                {
                    "encoding" : "base64"
                }
            ]
        })
    );

    let resp = post_json_honor_backoff(&rpc_url, &json_request).map_err(|e| format!("{}", e))?;

    let result_json = serde_json::from_reader(resp.into_reader()).map_err(|e| format!("{}", e))?;

    let result_json_string = format!("{}", result_json);

    match jv(result_json, "result") {
        Ok(serde_json::Value::String(s)) => {
            println!("Transaction signature: {}", s);
            let json_request = format!(
                "{}",
                serde_json::json!({
                    "jsonrpc" : "2.0",
                    "id" : 1,
                    "method" : "getTransaction",
                    "params" : [
                        s,
                        {
                            "commitment" : "finalized"
                        }
                    ]
                })
            );
            loop {
                let resp = post_json_honor_backoff(&rpc_url, &json_request).map_err(|e| format!("{}", e))?;

                let json_result = serde_json::from_reader(resp.into_reader()).map_err(|e| format!("{}", e))?;
                match jv(json_result, "result") {
                    Ok(serde_json::Value::Null) => {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    },
                    Ok(_) => {
                        return Ok(());
                    },
                    Err(err) => return Err(err)
                }
            }
        },
        Ok(v) => Err(stre(&format!("{}", v))),
        Err(_) => Err(stre(&result_json_string))
    }
}

fn print_pubkey_bytes(b : &[u8; 32])
{
    print!("[");
    let mut need_comma = false;
    b.iter().for_each(|b| {
        if need_comma {
            print!(",{}", b);
        }
        else {
            print!("{}", b);
            need_comma = true;
        }
    });
    print!("]");
}

fn print_pubkey_base64(b : &[u8; 32])
{
    println!("{}", base64::encode(&b));
}

fn do_pda(args : &mut std::env::Args) -> Result<(), Error>
{
    let mut args = args.peekable();

    // First argument may be "no-bump-seed"
    let no_bump_seed = args.next_if_eq("no-bump-seed").is_some();

    let bytes = args.next_if_eq("bytes").is_some();

    let mut words = Vec::<String>::new();

    args.for_each(|a| words.extend(make_words(&a)));

    let program_id = make_pubkey(&pubkey_from_words(&mut words)?)?;

    // Treat the remaining data values as if they were within a Vector, so that they are turned into a vector of Data
    // Values
    words.insert(0, "vector".to_string());

    let v = match read_data_value(&mut words)?.unwrap() {
        DataValue::Vector(v) => v,
        _ => panic!("Internal error - vector didn't parse")
    };

    let mut seed = vec![];
    for dv in v.into_iter() {
        write_c_value(*dv, false, &mut seed)?;
    }

    // Compute the address and bump seed, which may fail since a bump seed is not being used
    let (pda, bump_seed) = if no_bump_seed {
        try_find_pda(&program_id, &seed, None)
            .and_then(|pda| Some((pda, None)))
            .ok_or(stre("Cannot find PDA, consider allowing bump seed"))?
    }
    else {
        find_pda(&program_id, &seed).and_then(|(pda, bump_seed)| Some((pda, Some(bump_seed)))).unwrap()
    };

    if bytes {
        print_pubkey_bytes(&pda.0);
    }
    else {
        print!("{}", pda);
    }

    match bump_seed {
        Some(bump_seed) => println!(".{}", bump_seed),
        None => println!("")
    }

    Ok(())
}

fn do_pubkey(args : &mut std::env::Args) -> Result<(), Error>
{
    let mut args = args.peekable();

    // First argument may be "bytes"
    let mut bytes = false;
    let mut base64 = false;

    if args.next_if_eq("bytes").is_some() {
        bytes = true;
    }
    else if args.next_if_eq("base64").is_some() {
        base64 = true;
    }

    let mut words = Vec::<String>::new();

    args.for_each(|a| words.extend(make_words(&a)));

    let program_id = make_pubkey(&pubkey_from_words(&mut words)?)?;

    if bytes {
        print_pubkey_bytes(&program_id.0);
        println!("");
    }
    else if base64 {
        print_pubkey_base64(&program_id.0);
        println!("");
    }
    else {
        println!("{}", program_id);
    }

    Ok(())
}

fn do_main() -> Result<(), Error>
{
    let mut args = std::env::args();

    match args.nth(1) {
        Some(arg) => match arg.as_str() {
            "--help" | "help" => {
                let msg = match args.nth(0) {
                    Some(arg) => match arg.as_str() {
                        "encode" => &usage::ENCODE_USAGE_MESSAGE,
                        "decode" => &usage::DECODE_USAGE_MESSAGE,
                        "hash" => &usage::HASH_USAGE_MESSAGE,
                        "sign" => &usage::SIGN_USAGE_MESSAGE,
                        "show-unsigned" => &usage::SHOW_UNSIGNED_USAGE_MESSAGE,
                        "signature" => &usage::SIGNATURE_USAGE_MESSAGE,
                        "simulate" => &usage::SIMULATE_USAGE_MESSAGE,
                        "submit" => &usage::SUBMIT_USAGE_MESSAGE,
                        "pda" => &usage::PDA_USAGE_MESSAGE,
                        "pubkey" => &usage::PUBKEY_USAGE_MESSAGE,
                        _ => &usage::USAGE_MESSAGE
                    },
                    None => &usage::USAGE_MESSAGE
                };
                usage_exit(msg, None)
            },
            "encode" => do_encode(&mut args),
            "decode" => do_decode(),
            "hash" => do_hash(&mut args),
            "sign" => do_sign(&mut args),
            "show-unsigned" => do_show_unsigned(),
            "signature" => do_signature(),
            "simulate" => do_simulate(&mut args),
            "submit" => do_submit(&mut args),
            "pda" => do_pda(&mut args),
            "pubkey" => do_pubkey(&mut args),
            _ => Err(stre(&format!("Unknown command: {}", arg)))
        },
        None => usage_exit(usage::USAGE_MESSAGE, None)
    }
}

fn main()
{
    match do_main() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("");
            eprintln!("ERROR: {}", e);
            eprintln!("");
            eprintln!("Try 'solxact help' for help");
            std::process::exit(-1);
        }
    }
}
