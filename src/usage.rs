pub const USAGE_MESSAGE : &str = "
solxact is a utility program that can perform many useful actions on
solana transactions.

For help on subcommands:

solxact help encode        -- for encoding a transaction
solxact help decode        -- for decoding a transaction
solxact help hash          -- for setting the recent blockhash of a transaction
solxact help sign          -- for signing a transaction
solxact help show-unsigned -- for showing which signatures are still required
solxact help signature     -- for showing a transaction's signature
solxact help simulate      -- for simulating a transaction
solxact help submit        -- for submitting a transaction


Some example use cases of solxact:

# The following will create a split-stake transaction and submit it.  The
# format of the transaction was derived by looking at the stake program's
# \"Split\" instruction.  Note that comments can be embedded.

$ solxact encode encoding rust_bincode_fixedint                          \\
                 fee_payer ./my_key.json                                 \\
                 // Stake program //                                     \\
                 program Stake11111111111111111111111111111111111111     \\
                 // Stake account to split lamports from (writable) //   \\
                 account ./from_stake_account.json w                     \\
                 // Stake account to split lamports into (writable) //   \\
                 account ./to_stake_account.json w                       \\
                 // Stake withdraw authority (signer) //                 \\
                 account ./my_key.json s                                 \\
                 // Data: 3 = split-stake, and then lamports //          \\
                 enum 3 [ u64 10000000 ]                                 \\
  | solxact hash                                                         \\
  | solxact sign ./my_key.json                                           \\
  | solxact submit


# The following will create a simple lamports transfer transaction and
# then decode it and pretty-print the json output using 'jq'.

$ solxact encode encoding rust_bincode_fixedint                          \\
                 fee_payer ./my_key.json                                 \\
                 // System program //                                    \\
                 program 11111111111111111111111111111111                \\
                 // Funds source (writable and signer) //                \\
                 account ./my_key.json ws                                \\
                 // Funds destination (writable) //                      \\
                 account AVheJF4ZzCZjfysZP2FHdFERY3r7dh9AdBRRcJRWKARc w  \\
                 // Data: 2 = transfer, and then lamports //             \\
                 enum 2 [ u64 12131001000 ]                              \\
  | solxact decode                                                       \\
  | jq .


# The following reads an encoded transaction that was stored in a file
# and then simulates it using the testnet cluster, printing out the
# results of the simulation.

$ cat transaction.bin | solxact simulate testnet


# The following reads an encoded transaction from standard input and
# prints out the list of pubkeys that have not yet signed it.

$ solxact show-unsigned


# The following will create a simple lamports transfer transaction,
# apply a recent blockhash to it, sign it, and then print out the
# transaction signature.
  
$ solxact encode encoding rust_bincode_fixedint                          \\
                 fee_payer ./my_key.json                                 \\
                 // System program //                                    \\
                 program 11111111111111111111111111111111                \\
                 // Funds source (writable and signer) //                \\
                 account ./my_key.json ws                                \\
                 // Funds destination (writable) //                      \\
                 account AVheJF4ZzCZjfysZP2FHdFERY3r7dh9AdBRRcJRWKARc w  \\
                 // Data: 2 = transfer, and then lamports //             \\
                 enum 2 [ u64 12131001000 ]                              \\
  | solxact hash                                                         \\
  | solxact sign ./my_key.json                                           \\
  | solxact signature

";

pub const ENCODE_USAGE_MESSAGE : &str = "

solxact encode will encode components of a Solana transaction into a
complete transaction and write that transaction data to standard
output.  solana encode runs in two ways:

1. By specifying all arguments on the command line, or
2. By providing all arguments to be read from standard input

Attempting to mix these methods by providing both standard input and
command line arguments will produce an error.

The input to solxact describes a complete Solana transaction.  This
includes:
  - The transaction encoding style
  - The transaction fee payer account
  - A sequence of instructions to include in the transaction, which are
    composed of:
    - The program id of the program to invoke
    - The list of accounts that are to be passed to the program
    - A sequence of the data elements to encode in the data section of
      the transaction

To use solxact encode:

  solxact encode <ARGUMENTS>
  or
  command_that_produces_<ARGUMENTS> | solxact encode

The output is usually piped to another invocation of solxact that
performs operations such as signing or submitting the transaction
for execution, but may also be redirected into a file in order to
save the transaction for future use.

The arguments to solxact are drawn from the following set:

  encoding rust_bincode_varint | rust_bincode_fixedint | rust_borsh | c

      This argument sets the encoding to use when converting the data
      from the descriptive form provided to solxact, into binary data
      within the transaction.  The encoding may be one of:
        rust_bincode_varint: Encoded as a Rust program using bincode
          format with varint encoding would do
        rust_bincode_fixedint: Encoded as a Rust program using bincode
          format with fixedint encoding would do
        rust_borsh: Encoded as a Rust program using borsh format would
          do
        c: Encoded as a C program would do
      encoding is an optional argument; if it is not present, then
      rust_bincode_varint is assumed.

  fee_payer <PUBKEY>

      Supplies the fee payer to be used for paying the transaction fee.
      The <PUBKEY> argument is either a base58-encoded pubkey, or the
      path to a Solana json format key file from which the pubkey
      will be loaded.

  Sequence of instructions: after encoding and fee_payer, the remaining
  arguments describe a sequence of instructions to include in the
  transaction.  These all begin with a program argument that gives the
  program id of the program to invoke.  Instructions are added to the
  transaction in the order that they appear in the arguments.  The
  instruction sequence consists of:

  program <PUBKEY>

      Supplies the pubkey of the program to execute.  As with all
      <PUBKEY> arguments, this is either a base58-encoded pubkey or
      the path to a key file.

  account <PUBKEY> [w, s, ws, or sw]

      Identifies an account to be included in the instruction's account
      list.  Accounts are added to the instruction in the order that
      they appear in the arguments.  As with all <PUBKEY> arguments,
      this is either a base58-encoded pubkey or the path to a key file.
      Following the <PUBKEY>, an optional argument indicating whether
      the account is to be loaded as read-write (w), signed (s), or
      read-write and signed (ws or sw).  If no such argument is present,
      then the account is loaded read-only.

  Following the program and account arguments, a sequence of data
  arguments are provided that describe the data to encode into the data
  section of the instruction.  These arguments are drawn from the
  following list:

  bool <BOOLs>
  u8 <U8s>
  u16 <U16s>
  u32 <U32s>
  u64 <U64s>
  i8 <i8s>
  i16 <i16s>
  i32 <i32s>
  i64 <i64s>
  f32 <f32s>
  f64 <f64s>

     This is a whitespace-separated list of values of various types.
     The list is encoded as a direct sequence of values, NOT as a
     \"collection\" of values (and thus does not include a list length 
     encoded prefix).  A single value can be supplied; or more than one
     may be supplied as a convenience; e.g. instead of \"u8 6 u8 2 u8 100\"
     the syntax \"u8 6 2 100\" can be used.

  string <SINGLE_WORD>
  string \"<MULTI_WORD>\"

    This provides a string to encode into the data.  The string may be
    a single word (i.e. without whitespace), or may be a quoted string
    which can include whitespace.  Within a quoted string, \" is encoded
    as \\\" and \\ is encoded as \\\\.  Note that string cannot be used
    with the C language encoding, as the C language encoding is meant to
    encode C structs which cannot have variable length elements.  For
    C, use c_string instead.

  c_string <MAX_LENGTH> <SINGLE_WORD>
  c_string <MAX_LENGTH> \"<MULTI_WORD>\"

    The string is encoded into the data.  The format of the string
    encoding is C-language friendly: it is encoded as MAX_LENGTH bytes,
    with any bytes beyond the string contents encoded as zeroes.  This is
    the expected form of a string embedded within a C structure, since
    components of C structures cannot have variable length.

  pubkey <BASE58_OR_FILENAME>

    Encodes the 32 binary bytes of an ed25519 pubkey.  The pubkey is
    specified as a bas58-encoded public key, or as a file name from
    which a keypair will be read and the pubkey extracted from that
    keypair.

  vector [ <DATA_VALUEs> ]

    Encodes a \"collection\" of values, in the form that a vec would
    be encoded in Rust.  The DATA_VALUEs are a whitespace separated
    list of data values.  Note that vector cannot be used with the C
    language encoding, as the C language encoding is meant to encode
    encode C structs which cannot have variable length elements.

  struct [ <DATA_VALUEs> ]

    Encodes a \"struct\" of values; for Rust encodings, this would be
    as a Rust struct would be encoded if the Rust struct were composed
    of the given sequence of data values.  For C encodings, this would
    be as a C struct would be encoded if the C struct were composed
    of the given sequence of data values.

  enum <INDEX>
  enum <INDEX> [ <DATA_VALUEs> ]

    Encodes an \"enum\" value which may have additional enum parameters
    to encode.  The <INDEX> of the enum element is provided, and
    optionally a sequence of DATA_VALUEs to encode as parameters of
    that enum.

  some <DATA_VALUE>

    Encodes a Rust-style Option value, where the Option is
    Some(DATA_VALUE).

  none

    Encodes a Rust-style Option value, where the Option is None.

  In addition, comments that begin with \"//\" and end with \"//\"
  will be ignored.

";

pub const DECODE_USAGE_MESSAGE : &str = "

solxact decode will read an encoded transaction from standard input
and write a human-readable decoded version of that transaction in
json format to standard output.

";

pub const HASH_USAGE_MESSAGE : &str = "

solxact hash will read an encoded transaction from standard input,
and will look up the most recent blockhash from an RPC node and
apply that recent blockhash to the transaction.  It will then re-
encode the transaction and write its encoded form to standard
output.

solxact hash when invoked with zero arguments will fetch the most
recent blockhash of the Solana mainnet cluster from the standard
Solana mainnet RPC node.

The URL of the RPC node to query can be passed as the only
command-nline argument accepted by solxact hash.

For example, the following command will fetch a most recent blockhash
     
for the Solana devnet cluster:

$ solxact hash https://api.devnet.solana.com

The following cluster identifiers may be used to refer to specific
clusters:

l, localhost -- http://127.0.0.7:8899
d, devnet -- https://api.devnet.solana.com
t, testnet -- https://api.testnet.solana.com
m, mainnet -- https://api.mainnet-beta.solana.com

For example, the following will fetch the most recent blockhash
from the testnet cluster:

$ solxact hash t

";

pub const SIGN_USAGE_MESSAGE : &str = "

solxact decode will read an encoded transaction from standard
input, apply any needed signatures using keys provided as command
line arguments, then re-encode and write the signed transaction to
standard output.

The arguments to solxact decode are all key files which are to be
used to supply signatures for the transaction.

For example, the following command would sign a transaction using
two keys:

$ solxact sign ./my_key.json ./my_admin_key.json

";

pub const SHOW_UNSIGNED_USAGE_MESSAGE : &str = "

solxact decode will read an encoded transaction from standard
input and print out the pubkeys of any signer that is required
to sign the transaction but has not yet done so.
";

pub const SIGNATURE_USAGE_MESSAGE : &str = "

solxact signature will read an encoded transaction from standard
input and print out the signature of the transaction.  The
signature of solana transactions (sometimes called the transaction
id) is the fee payer's signature.

";

pub const SIMULATE_USAGE_MESSAGE : &str = "

solxact simulate will read an encoded transaction from standard
input and simulate its execution for a given cluster.  It will
print to standard output the json-encoded results of simulating
the transaction.

If no arguments are passed to solxact simulate, then the mainnet
cluster will be used for the simulation.  If a single argument
is passed to solxact simulate, it is the URL of the RPC node to
be used to perform the simulation.

For example, the following will simulate the transaction
execution on the devnet cluster:

$ solxact simulate https://api.devnet.solana.com

The following cluster identifiers may be used to refer to specific
clusters:

l, localhost -- http://127.0.0.7:8899
d, devnet -- https://api.devnet.solana.com
t, testnet -- https://api.testnet.solana.com
m, mainnet -- https://api.mainnet-beta.solana.com

For example, the following will simulate the transaction on the
testnet cluster:

$ solxact simulate t

Note that transactions that are simulated do not need to be
signed or have their most recent blockhash applied.

";

pub const SUBMIT_USAGE_MESSAGE : &str = "

solxact submit will read an encoded transaction from standard
input and submit it to a cluster for execution. It will wait
for the transaction to be executed and then print to standard
out the json-encoded results of simulating the transaction.

If no arguments are passed to solxact submit, then the mainnet
cluster will be used for the submission.  If a single argument
is passed to solxact submit, it is the URL of the RPC node to
be used to submit the transaction to a cluster.

For example, the following will execute the transaction on the
devnet cluster:

$ solxact submit https://api.devnet.solana.com

The following cluster identifiers may be used to refer to specific
clusters:

l, localhost -- http://127.0.0.7:8899
d, devnet -- https://api.devnet.solana.com
t, testnet -- https://api.testnet.solana.com
m, mainnet -- https://api.mainnet-beta.solana.com

For example, the following will submit the transaction to the
testnet cluster:

$ solxact submit testnet

Note that transactions that are submitted must have a valid
recent blockhash supplied (e.g. via solxact hash) and be signed
(e.g. via solxact sign).

";
