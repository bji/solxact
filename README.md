```
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
# "Split" instruction.  Note that comments can be embedded.

$ solxact encode encoding rust_bincode_fixedint                          \
                 fee_payer ./my_key.json                                 \
                 // Stake program //                                     \
                 program Stake11111111111111111111111111111111111111     \
                 // Stake account to split lamports from (writable) //   \
                 account ./from_stake_account.json w                     \
                 // Stake account to split lamports into (writable) //   \
                 account ./to_stake_account.json w                       \
                 // Stake withdraw authority (signer) //                 \
                 account ./my_key.json s                                 \
                 // Data: 3 = split-stake, and then lamports //          \
                 enum 3 [ u64 10000000 ]                                 \
  | solxact hash                                                         \
  | solxact sign ./my_key.json                                           \
  | solxact submit


# The following will create a simple lamports transfer transaction and
# then decode it and pretty-print the json output using 'jq'.

$ solxact encode encoding rust_bincode_fixedint                          \
                 fee_payer ./my_key.json                                 \
                 // System program //                                    \
                 program 11111111111111111111111111111111                \
                 // Funds source (writable and signer) //                \
                 account ./my_key.json ws                                \
                 // Funds destination (writable) //                      \
                 account AVheJF4ZzCZjfysZP2FHdFERY3r7dh9AdBRRcJRWKARc w  \
                 // Data: 2 = transfer, and then lamports //             \
                 enum 2 [ u64 12131001000 ]                              \
  | solxact decode                                                       \
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
  
$ solxact encode encoding rust_bincode_fixedint                          \
                 fee_payer ./my_key.json                                 \
                 // System program //                                    \
                 program 11111111111111111111111111111111                \
                 // Funds source (writable and signer) //                \
                 account ./my_key.json ws                                \
                 // Funds destination (writable) //                      \
                 account AVheJF4ZzCZjfysZP2FHdFERY3r7dh9AdBRRcJRWKARc w  \
                 // Data: 2 = transfer, and then lamports //             \
                 enum 2 [ u64 12131001000 ]                              \
  | solxact hash                                                         \
  | solxact sign ./my_key.json                                           \
  | solxact signature
```
