use crate::{stre, Error};
use serde_json::{Map as json_Map, Number as json_Number, Value as json_Value};

// This comes from solana validator code base, which requires all transactions to fit inside an IPV4 UDP packet
// minus some overhead
pub const _MAXIMUM_TRANSACTION_BYTES : u16 = 1232;

// (1232 - (4 + 32 + 1) - 1) / 64
pub const MAXIMUM_ED25519_SIGNATURES_COUNT : u8 = 18;

// (1232 - (1 + 32 + 1) - 4) / 32
pub const MAXIMUM_ADDRESSES_COUNT : u8 = 37;

// (1232 - (1 + 4 + 32) - (1 + 1 + 2 + 1))
pub const MAXIMUM_INSTRUCTION_ADDRESS_INDEX_COUNT : u16 = 1190;

// (1232 - (1 + 4 + 32) - 1) - 2
pub const MAXIMUM_INSTRUCTION_DATA_COUNT : u16 = 1192;

// (1232 - (1 + 4 + 32) - 2) / 3
pub const _MAXIMUM_INSTRUCTIONS_COUNT : u16 = 397;

#[derive(Clone, PartialEq)]
pub struct Address(pub [u8; 32]);

#[derive(Clone, PartialEq)]
pub struct Pubkey(pub [u8; 32]);

#[derive(Clone)]
pub struct PubkeyWithSignature
{
    pub pubkey : Pubkey,

    pub signature : Option<ed25519_dalek::Signature>
}

#[derive(PartialEq, Clone)]
pub struct Sha256Digest(pub [u8; 32]);

pub struct Transaction
{
    pub signed_read_write_addresses : Vec<PubkeyWithSignature>,

    pub signed_read_only_addresses : Vec<PubkeyWithSignature>,

    pub unsigned_read_write_addresses : Vec<Address>,

    pub unsigned_read_only_addresses : Vec<Address>,

    pub recent_blockhash : Option<Sha256Digest>,

    pub instructions : Vec<Instruction>
}

pub struct Instruction
{
    pub program_address : Address,

    // (address, is_signed, is_read_write)
    pub addresses : Vec<(Address, bool, bool)>,

    pub data : Vec<u8>
}

const EMPTY_RECENT_BLOCKHASH : Sha256Digest = Sha256Digest([0_u8; 32]);

const EMPTY_SIGNATURE_BYTES : [u8; 64] = [0_u8; 64];

impl Transaction
{
    pub fn new(fee_payer : Pubkey) -> Self
    {
        Transaction {
            signed_read_write_addresses : vec![PubkeyWithSignature { pubkey : fee_payer, signature : None }],
            signed_read_only_addresses : vec![],
            unsigned_read_write_addresses : vec![],
            unsigned_read_only_addresses : vec![],
            recent_blockhash : None,
            instructions : vec![]
        }
    }

    pub fn add_instruction(
        &mut self,
        instruction : Instruction
    )
    {
        self.add_address(&instruction.program_address, false);

        instruction.addresses.iter().for_each(|(address, is_signed, is_read_write)| {
            if *is_signed {
                self.add_signature(&Pubkey(address.0), *is_read_write);
            }
            else {
                self.add_address(&address, *is_read_write);
            }
        });

        self.instructions.push(instruction);
    }

    pub fn decode(r : &mut dyn std::io::Read) -> Result<Self, Error>
    {
        let signatures_count = Self::decode_compact_u16(r)?;

        // Can't provide more signatures than allowed
        if signatures_count > (MAXIMUM_ED25519_SIGNATURES_COUNT as u16) {
            return Err(stre(&format!(
                "Too many signatures in transaction: expected at most {}, got {}",
                MAXIMUM_ED25519_SIGNATURES_COUNT, signatures_count
            )));
        }

        let mut signatures = Vec::<Option<ed25519_dalek::Signature>>::new();

        let mut buf = [0_u8; 64];

        for _ in 0..signatures_count {
            Self::read(r, &mut buf)?;
            signatures.push(if buf == EMPTY_SIGNATURE_BYTES {
                None
            }
            else {
                Some(ed25519_dalek::Signature::from_bytes(&buf).map_err(|e| format!("{}", e))?)
            });
        }

        Self::read(r, &mut buf[0..3])?;

        let total_signed_address_count = buf[0] as u16;

        if total_signed_address_count > (MAXIMUM_ADDRESSES_COUNT as u16) {
            return Err(stre(&format!(
                "Too many signatures supplied: expected at most {}, got {}",
                total_signed_address_count, MAXIMUM_ADDRESSES_COUNT
            )));
        }

        // Our encoder always produces all signatures, but uses all zero signatures for those signatures which were
        // not provided.  Other implementations may instead produce a short signatures list, which can only be
        // signatures in order, with unsupplied signatures being zero.
        if signatures_count > total_signed_address_count {
            return Err(stre(&format!(
                "Too many signatures supplied: expected at most {}, got {}",
                total_signed_address_count, signatures_count
            )));
        }

        let signed_read_only_address_count = buf[1] as u16;

        if signed_read_only_address_count > total_signed_address_count {
            return Err(stre(&format!(
                "Too many signed read only addresses: expected at most {}, got {}",
                total_signed_address_count, signed_read_only_address_count
            )));
        }

        let signed_read_write_address_count = total_signed_address_count - signed_read_only_address_count;

        if signed_read_write_address_count == 0 {
            return Err(stre("Minimum signed address count of 1 required for fee payer"));
        }

        let unsigned_read_only_address_count = buf[2] as u16;

        let minimum_address_count = total_signed_address_count + unsigned_read_only_address_count;

        let actual_address_count = Self::decode_compact_u16(r)?;

        if actual_address_count < minimum_address_count {
            return Err(stre(&format!(
                "Too few addresses in header; {} supplied but at least {} required",
                actual_address_count, minimum_address_count
            )));
        }

        let unsigned_read_write_address_count = actual_address_count - minimum_address_count;

        let mut ret = Transaction {
            signed_read_write_addresses : vec![],
            signed_read_only_addresses : vec![],
            unsigned_read_write_addresses : vec![],
            unsigned_read_only_addresses : vec![],
            recent_blockhash : None,
            instructions : vec![]
        };

        let mut signatures_iter = signatures.into_iter();

        for _ in 0..signed_read_write_address_count {
            ret.signed_read_write_addresses.push(Self::decode_signature_from_header(&mut signatures_iter, r)?);
        }

        for _ in 0..signed_read_only_address_count {
            ret.signed_read_only_addresses.push(Self::decode_signature_from_header(&mut signatures_iter, r)?);
        }

        for _ in 0..unsigned_read_write_address_count {
            ret.unsigned_read_write_addresses.push(Self::decode_address(r)?);
        }

        for _ in 0..unsigned_read_only_address_count {
            ret.unsigned_read_only_addresses.push(Self::decode_address(r)?);
        }

        ret.recent_blockhash = Self::decode_recent_blockhash(r)?;

        let instruction_count = Self::decode_compact_u16(r)?;

        for i in 0..instruction_count {
            let i = i as usize;
            Self::read(r, &mut buf[0..1])?;

            let program_address = ret
                .find_address_at_index(buf[0])
                .ok_or(format!("Invalid program id index {} for instruction {}", buf[0], i))?;

            let addresses_count = Self::decode_compact_u16(r)?;

            if addresses_count > MAXIMUM_INSTRUCTION_ADDRESS_INDEX_COUNT {
                return Err(stre(&format!(
                    "Too many addresses in instruction {}: expected at most {} got {}",
                    i, MAXIMUM_INSTRUCTION_ADDRESS_INDEX_COUNT, addresses_count
                )));
            }

            let mut addresses = Vec::<(Address, bool, bool)>::new();

            for _ in 0..addresses_count {
                Self::read(r, &mut buf[0..1])?;
                addresses.push(
                    ret.find_address_at_index(buf[0])
                        .ok_or(format!("Invalid address index {} referenced from instruction {}", buf[0], i))?
                );
            }

            let data_count = Self::decode_compact_u16(r)?;

            if data_count > MAXIMUM_INSTRUCTION_DATA_COUNT {
                return Err(stre(&format!(
                    "Too many data bytes in instruction {}: expected at most {} got {}",
                    i, MAXIMUM_INSTRUCTION_DATA_COUNT, data_count
                )));
            }

            let mut data = vec![0_u8; data_count as usize];

            Self::read(r, &mut data)?;

            ret.instructions.push(Instruction { program_address : program_address.0, addresses, data });
        }

        Ok(ret)
    }

    // Return the message bytes of the transaction.
    pub fn message(
        &self,
        w : &mut dyn std::io::Write
    ) -> Result<(), Error>
    {
        u8::try_from(self.signed_read_write_addresses.len() + self.signed_read_only_addresses.len())
            .or(Err(stre("Too many signed addresses")))
            .and_then(|u| Self::write(w, &[u]))?;

        u8::try_from(self.signed_read_only_addresses.len())
            .or(Err(stre("Too many read only addresses")))
            .and_then(|u| Self::write(w, &[u]))?;

        Self::write(w, &[self.unsigned_read_only_addresses.len() as u8])?;

        let recent_blockhash = self.recent_blockhash.as_ref().unwrap_or(&EMPTY_RECENT_BLOCKHASH);

        if self.instructions.len() > (u16::MAX as usize) {
            return Err(stre("Too many instructions"));
        }

        // compact-array of account addresses
        Self::encode_compact_u16(
            (self.signed_read_write_addresses.len() +
                self.signed_read_only_addresses.len() +
                self.unsigned_read_write_addresses.len() +
                self.unsigned_read_only_addresses.len()) as u16,
            w
        )?;

        for a in self
            .signed_read_write_addresses
            .iter()
            .chain(self.signed_read_only_addresses.iter())
            .map(|s| &s.pubkey.0)
            .chain(
                self.unsigned_read_write_addresses.iter().chain(self.unsigned_read_only_addresses.iter()).map(|a| &a.0)
            )
        {
            Self::write(w, a)?;
        }

        // recent blockhash
        Self::write(w, &recent_blockhash.0)?;

        // instructions
        Self::encode_compact_u16(self.instructions.len() as u16, w)?;

        for instruction in &self.instructions {
            // instruction program_id index
            Self::write(
                w,
                std::slice::from_ref(&self.find_address_index(&instruction.program_address).ok_or(format!(
                    "Invalid Transaction - program address {} not in address list",
                    instruction.program_address
                ))?)
            )?;

            // instruction address indices
            Self::encode_compact_u16(instruction.addresses.len() as u16, w)?;
            for a in &instruction.addresses {
                Self::write(
                    w,
                    std::slice::from_ref(
                        &self
                            .find_address_index(&a.0)
                            .ok_or(format!("Invalid Transaction - address {} is not in address list", a.0))?
                    )
                )?;
            }

            // instruction data
            let data_len = instruction.data.len();
            if data_len > (MAXIMUM_INSTRUCTION_DATA_COUNT as usize) {
                return Err(stre(&format!(
                    "Instruction data len too long: {} > {}",
                    data_len, MAXIMUM_INSTRUCTION_DATA_COUNT
                )));
            }
            Self::encode_compact_u16(data_len as u16, w)?;
            Self::write(w, instruction.data.as_slice())?;
        }
        Ok(())
    }

    // Iterates over addresses that still need to provide a signature
    pub fn needed_signatures(&self) -> impl Iterator<Item = Pubkey>
    {
        let mut v : Vec<Pubkey> = self
            .signed_read_write_addresses
            .iter()
            .filter_map(|a| {
                if a.signature.is_some() {
                    None
                }
                else {
                    Some(a.pubkey.clone())
                }
            })
            .chain(self.signed_read_only_addresses.iter().filter_map(|a| {
                if a.signature.is_some() {
                    None
                }
                else {
                    Some(a.pubkey.clone())
                }
            }))
            .collect();

        v.sort_by_key(|a| format!("{}", a));

        v.dedup();

        v.into_iter()
    }

    // Adds a signature to the transaction, which adds the pubkey that is signed to the signed address list.
    pub fn add_signature(
        &mut self,
        pubkey : &Pubkey,
        is_read_write : bool
    )
    {
        if is_read_write {
            if let Some(_) = self.signed_read_write_addresses.iter().position(|x| x.pubkey == *pubkey) {
                // Already exists as signed read-write
            }
            else {
                if let Some(pos) = self.signed_read_only_addresses.iter().position(|x| x.pubkey == *pubkey) {
                    // Promote
                    self.signed_read_only_addresses.remove(pos);
                }
                else if let Some(pos) = self.unsigned_read_write_addresses.iter().position(|x| x == pubkey) {
                    // Promote
                    self.unsigned_read_write_addresses.remove(pos);
                }
                // Add to signed read_write
                self.signed_read_write_addresses
                    .push(PubkeyWithSignature { pubkey : pubkey.clone(), signature : None });
            }
        }
        else if let Some(_) = self.signed_read_write_addresses.iter().position(|x| x.pubkey == *pubkey) {
            // Already exists as signed read-write which supercedes signed read-only
        }
        else if let Some(_) = self.signed_read_only_addresses.iter().position(|x| x.pubkey == *pubkey) {
            // Already exists as signed read-only
        }
        else if let Some(pos) = self.unsigned_read_write_addresses.iter().position(|x| x == pubkey) {
            // Promote
            self.unsigned_read_write_addresses.remove(pos);
            self.signed_read_write_addresses.push(PubkeyWithSignature { pubkey : pubkey.clone(), signature : None });
        }
        else {
            if let Some(pos) = self.unsigned_read_only_addresses.iter().position(|x| x == pubkey) {
                // Promote
                self.unsigned_read_only_addresses.remove(pos);
            }
            self.signed_read_only_addresses.push(PubkeyWithSignature { pubkey : pubkey.clone(), signature : None });
        }
    }

    // Adds an unsigned address to the transaction, which adds it to the unsigned address list.  The fee payer must
    // already have been set.
    pub fn add_address(
        &mut self,
        address : &Address,
        is_read_write : bool
    )
    {
        if is_read_write {
            if let Some(_) = self.signed_read_write_addresses.iter().position(|x| *address == x.pubkey) {
                // Already exists as signed read-write
            }
            else if let Some(pos) = self.signed_read_only_addresses.iter().position(|x| *address == x.pubkey) {
                // Promote to signed read-write
                self.signed_read_only_addresses.remove(pos);
                self.signed_read_write_addresses
                    .push(PubkeyWithSignature { pubkey : address.clone().into(), signature : None });
            }
            else if let Some(_) = self.unsigned_read_write_addresses.iter().position(|x| address == x) {
                // Already exists as unsigned read-write
            }
            else {
                if let Some(pos) = self.unsigned_read_only_addresses.iter().position(|x| address == x) {
                    // Promote to unsigned read-write
                    self.unsigned_read_only_addresses.remove(pos);
                }
                self.unsigned_read_write_addresses.push(address.clone())
            }
        }
        else if let Some(_) = self.signed_read_write_addresses.iter().position(|x| *address == x.pubkey) {
            // Already exists as signed read-write which supercedes unsigned read-only
        }
        else if let Some(_) = self.signed_read_only_addresses.iter().position(|x| *address == x.pubkey) {
            // Already exists as signed read-only which supercedes unsigned read-only
        }
        else if let Some(_) = self.unsigned_read_write_addresses.iter().position(|x| address == x) {
            // Already exists as unsigned read-write, which supercedes unsigned read-only
        }
        else if let Some(_) = self.unsigned_read_only_addresses.iter().position(|x| address == x) {
            // Already exists as unsigned read-only
        }
        else {
            // Add to unsigned read_only
            self.unsigned_read_only_addresses.push(address.clone());
        }
    }

    // Set the recent_blockhash of the transaction.  If it is different than the current recent_blockhash of this
    // Transaction, all signatures of the transaction will be cleared since they are no longer valid as the message
    // contents have changed.
    pub fn set_recent_blockhash(
        &mut self,
        recent_blockhash : Sha256Digest
    )
    {
        let recent_blockhash = Some(recent_blockhash);

        if recent_blockhash != self.recent_blockhash {
            self.recent_blockhash = recent_blockhash;
            self.signed_read_write_addresses.iter_mut().for_each(|s| s.signature = None);
            self.signed_read_only_addresses.iter_mut().for_each(|s| s.signature = None);
        }
    }

    pub fn sign(
        &mut self,
        pubkey : &Pubkey,
        signature : ed25519_dalek::Signature
    ) -> Result<(), Error>
    {
        for i in 0..self.signed_read_write_addresses.len() {
            if self.signed_read_write_addresses[i].pubkey == *pubkey {
                self.signed_read_write_addresses[i].signature = Some(signature);
            }
        }

        for i in 0..self.signed_read_only_addresses.len() {
            if self.signed_read_only_addresses[i].pubkey == *pubkey {
                self.signed_read_only_addresses[i].signature = Some(signature);
            }
        }

        Ok(())
    }

    pub fn encode(
        &self,
        w : &mut dyn std::io::Write
    ) -> Result<(), Error>
    {
        let total_signatures = self.signed_read_write_addresses.len() + self.signed_read_only_addresses.len();

        if total_signatures > (u16::MAX as usize) {
            return Err(stre("Too many addresses"));
        }

        Self::encode_compact_u16(total_signatures as u16, w)?;

        for signature in self.signed_read_write_addresses.iter().chain(&self.signed_read_only_addresses) {
            Self::encode_signature(signature.signature, w)?;
        }

        self.message(w)
    }

    fn decode_compact_u16(r : &mut dyn std::io::Read) -> Result<u16, Error>
    {
        let mut buf = [0_u8; 3];

        Self::read(r, &mut buf[0..1])?;

        if (buf[0] & 0x80) == 0x80 {
            Self::read(r, &mut buf[1..2])?;
            if buf[1] & 0x80 == 0x80 {
                Self::read(r, &mut buf[2..3])?;
                Ok((((buf[0] as u16) & !0x80) << 0) |
                    (((buf[1] as u16) & !0x80) << 7) |
                    (((buf[2] as u16) & !0x00) << 14))
            }
            else {
                Ok((((buf[0] as u16) & !0x80) << 0) | (((buf[1] as u16) & !0x80) << 7))
            }
        }
        else {
            Ok(buf[0] as u16)
        }
    }

    fn decode_signature_from_header(
        signatures : impl IntoIterator<Item = Option<ed25519_dalek::Signature>>,
        r : &mut dyn std::io::Read
    ) -> Result<PubkeyWithSignature, Error>
    {
        let address = Self::decode_address(r)?;

        Ok(PubkeyWithSignature {
            pubkey : Pubkey(address.0),
            signature : signatures.into_iter().next().unwrap_or(None)
        })
    }

    fn decode_address(r : &mut dyn std::io::Read) -> Result<Address, Error>
    {
        let mut buf = [0_u8; 32];
        Self::read(r, &mut buf)?;
        Ok(Address(buf))
    }

    fn decode_recent_blockhash(r : &mut dyn std::io::Read) -> Result<Option<Sha256Digest>, Error>
    {
        let mut buf = [0_u8; 32];

        Self::read(r, &mut buf)?;

        if buf == EMPTY_RECENT_BLOCKHASH.0 {
            Ok(None)
        }
        else {
            Ok(Some(Sha256Digest(buf)))
        }
    }

    // Searching is done irrespective of account permissions.  This matches the expected Solana runtime behavior,
    // where the execution system will perform a similar action.  It is technically possible to encode the same
    // address with multiple permissions versions, but the runtime will reject such a transaction with an error about
    // "Account loaded twice"
    fn find_address_index(
        &self,
        address : &Address
    ) -> Option<u8>
    {
        match self.signed_read_write_addresses.iter().position(|s| address == &s.pubkey) {
            Some(index) => return Some(index as u8),
            None => ()
        }

        let mut offset = self.signed_read_write_addresses.len();

        match self.signed_read_only_addresses.iter().position(|s| address == &s.pubkey) {
            Some(index) => return Some((index + offset) as u8),
            None => ()
        }

        offset += self.signed_read_only_addresses.len();

        match self.unsigned_read_write_addresses.iter().position(|a| address == a) {
            Some(index) => return Some((index + offset) as u8),
            None => ()
        }

        offset += self.unsigned_read_write_addresses.len();

        match self.unsigned_read_only_addresses.iter().position(|a| address == a) {
            Some(index) => Some((index + offset) as u8),
            None => None
        }
    }

    // Returns (address, is_signed, read_write)
    fn find_address_at_index(
        &self,
        index : u8
    ) -> Option<(Address, bool, bool)>
    {
        let mut uindex = index as usize;

        if uindex < self.signed_read_write_addresses.len() {
            return Some((Address(self.signed_read_write_addresses[uindex].pubkey.0), true, true));
        }

        uindex -= self.signed_read_write_addresses.len();

        if uindex < self.signed_read_only_addresses.len() {
            return Some((Address(self.signed_read_only_addresses[uindex].pubkey.0), true, false));
        }

        uindex -= self.signed_read_only_addresses.len();

        if uindex < self.unsigned_read_write_addresses.len() {
            return Some((Address(self.unsigned_read_write_addresses[uindex].0), false, true));
        }

        uindex -= self.unsigned_read_write_addresses.len();

        if uindex < self.unsigned_read_only_addresses.len() {
            return Some((Address(self.unsigned_read_only_addresses[uindex].0), false, false));
        }

        None
    }

    fn encode_compact_u16(
        mut u : u16,
        w : &mut dyn std::io::Write
    ) -> Result<(), Error>
    {
        let mut buf = [0_u8; 3];

        let mut v = (u & 0x7F) as u8;
        if u > 0x7F {
            buf[0] = v | 0x80;
            u >>= 7;
            v = (u & 0x7F) as u8;
            if u > 0x7F {
                buf[1] = v | 0x80;
                buf[2] = (u >> 7) as u8;
                Self::write(w, &buf)
            }
            else {
                buf[1] = v;
                Self::write(w, &buf[0..2])
            }
        }
        else {
            buf[0] = v;
            Self::write(w, &buf[0..1])
        }
    }

    fn encode_signature(
        signature : Option<ed25519_dalek::Signature>,
        w : &mut dyn std::io::Write
    ) -> Result<(), Error>
    {
        Self::write(w, signature.map(|s| s.to_bytes()).unwrap_or(EMPTY_SIGNATURE_BYTES).as_slice())
    }

    fn read(
        r : &mut dyn std::io::Read,
        buf : &mut [u8]
    ) -> Result<(), Error>
    {
        r.read_exact(buf).map_err(|e| e.into())
    }

    fn write(
        w : &mut dyn std::io::Write,
        buf : &[u8]
    ) -> Result<(), Error>
    {
        w.write_all(&buf).map_err(|e| e.into())
    }
}

fn convert_address(
    address : &Address,
    is_signed : bool,
    is_read_write : bool,
    has_signature : Option<bool>
) -> json_Value
{
    let address = json_Value::String(format!("{}", address));

    let mut map = json_Map::<String, json_Value>::new();

    map.insert("address".to_string(), address);

    if is_signed {
        map.insert("is_signed".to_string(), json_Value::Bool(true));
        if let Some(has_signature) = has_signature {
            if !has_signature {
                map.insert("has_signature".to_string(), json_Value::Bool(false));
            }
        }
    }

    map.insert("is_read_write".to_string(), json_Value::Bool(is_read_write));

    json_Value::Object(map)
}

fn convert_instruction(instruction : &Instruction) -> json_Value
{
    let mut map = json_Map::<String, json_Value>::new();

    map.insert("program_id".to_string(), json_Value::String(format!("{}", instruction.program_address)));

    let addresses : Vec<json_Value> =
        instruction.addresses.iter().map(|a| convert_address(&a.0, a.1, a.2, None)).collect();

    if addresses.len() > 0 {
        map.insert("addresses".to_string(), json_Value::Array(addresses));
    }

    map.insert(
        "data".to_string(),
        json_Value::Array(instruction.data.iter().map(|v| json_Value::Number(json_Number::from(*v))).collect())
    );

    json_Value::Object(map)
}

impl std::fmt::Display for Transaction
{
    fn fmt(
        &self,
        f : &mut std::fmt::Formatter
    ) -> std::fmt::Result
    {
        let mut top_map = json_Map::<String, json_Value>::new();

        let mut addresses = Vec::<json_Value>::new();

        for s in &self.signed_read_write_addresses {
            addresses.push(convert_address(&Address(s.pubkey.0), true, true, Some(s.signature.is_some())));
        }

        for s in &self.signed_read_only_addresses {
            addresses.push(convert_address(&Address(s.pubkey.0), true, false, Some(s.signature.is_some())));
        }

        for a in &self.unsigned_read_write_addresses {
            addresses.push(convert_address(&a, false, true, None));
        }

        for a in &self.unsigned_read_only_addresses {
            addresses.push(convert_address(&a, false, false, None));
        }

        if addresses.len() > 0 {
            // Add a "fee_payer" to first address
            match &mut addresses[0] {
                json_Value::Object(map) => {
                    map.insert("fee_payer".to_string(), json_Value::Bool(true));
                    ()
                },
                _ => ()
            }
            top_map.insert("addresses".to_string(), json_Value::Array(addresses));
        }

        if let Some(recent_blockhash) = &self.recent_blockhash {
            top_map.insert("recent_blockhash".to_string(), json_Value::String(format!("{}", recent_blockhash)));
        }

        top_map.insert("instructions".to_string(), self.instructions.iter().map(|i| convert_instruction(i)).collect());

        write!(f, "{}", json_Value::to_string(&json_Value::Object(top_map)))
    }
}

impl std::fmt::Display for Address
{
    fn fmt(
        &self,
        f : &mut std::fmt::Formatter
    ) -> std::fmt::Result
    {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl std::str::FromStr for Address
{
    type Err = String;

    fn from_str(s : &str) -> Result<Self, Self::Err>
    {
        let mut address = [0_u8; 32];

        let v = bs58::decode(s).into_vec().map_err(|e| format!("{}", e))?;

        if v.len() == 32 {
            address.copy_from_slice(v.as_slice());
            Ok(Address(address))
        }
        else {
            Err(format!("Invalid address {}", s))
        }
    }
}

impl std::convert::From<Pubkey> for Address
{
    fn from(p : Pubkey) -> Self
    {
        Self(p.0)
    }
}

impl PartialEq<Pubkey> for Address
{
    fn eq(
        &self,
        other : &Pubkey
    ) -> bool
    {
        self.0 == other.0
    }
}

impl std::fmt::Display for Pubkey
{
    fn fmt(
        &self,
        f : &mut std::fmt::Formatter
    ) -> std::fmt::Result
    {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl std::str::FromStr for Pubkey
{
    type Err = String;

    fn from_str(s : &str) -> Result<Self, Self::Err>
    {
        let a = Address::from_str(s)?;

        Ok(Pubkey(a.0))
    }
}

impl std::convert::From<Address> for Pubkey
{
    fn from(a : Address) -> Self
    {
        Self(a.0)
    }
}

impl std::fmt::Display for Sha256Digest
{
    fn fmt(
        &self,
        f : &mut std::fmt::Formatter
    ) -> std::fmt::Result
    {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl std::str::FromStr for Sha256Digest
{
    type Err = String;

    fn from_str(s : &str) -> Result<Self, Self::Err>
    {
        let mut digest = [0_u8; 32];

        let v = bs58::decode(s).into_vec().map_err(|e| format!("{}", e))?;

        if v.len() == 32 {
            digest.copy_from_slice(v.as_slice());
            Ok(Sha256Digest(digest))
        }
        else {
            Err(format!("Invalid SHA-256 digest {}", s))
        }
    }
}
