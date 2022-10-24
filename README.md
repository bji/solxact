```
$ solxact help

solxact is a utility program that allows the creation, manipulation,
execution, simulation, and decoding of solana transactions.

Usage:

solxact --help/-h/help

   Prints usage information to stdout and exits.


solxact --gendata <OPTIONS> <schema> -- [name=value..]

  Generates a data file to be filled in with values required by
  the schema and prints it to standard out.  <schema> is either
  a path name of a transaction schema file, or the name of a transaction
  schema located in the schema_dir as <schema>.json.

  Available options:
    --stdin: read data values from stdin and use them rather than blank
        values
    --schema-dir <SCHEMA_DIR>: sets the directory from which schema files
        will be read (default: ./schema)

  Any name=value sequence following -- will provide the value 'value' for
  the input named 'name' within the schema.


solxact [--generate] --fee-payer <fee_payer> \
                     <OPTIONS> <schema> [<data_file>] -- [name=value..]

  Generates a transaction from a transaction and supplied input values.
  <schema> is either a path name of a transaction schema file, or the name of
  a transaction schema located in the schema_dir as <schema>.json.

  Available options:
    --stdin: read data values from stdin that in preference to values in
        in <data_file>
    --schema-dir <SCHEMA_DIR>  (default: ./schema)

  This will use the given <schema_file> with data provided by the
  following sources:

    Any command-line provided name=value pars following -- will provide the
    value 'value' for the input 'name'.

    For any value not specified on the command line or standard input,
    <data_file>, if specified, will be queried.

  Note that --generate is optional; this is the default behavior if no other
  option is present directing solxact to operate in a different mode.

  Examples:
  
      solxact --generate --fee-payer "foo" my_schema \
          my_data.json > my_transaction

      This will read schema from ./schema/my_schema.json, read data values from
      my_data.json, and write the generated transaction to stdout which is then
      redirected into my_transaction.

      solxact --fee-payer "foo" --stdin ./my_schema.json

      This will read schema from ./my_schema.json, read data values from stdin ,
      and write the resulting transaction to stdout.


solxact --genweb3js <OPTIONS> <schema>

  Generate a javascript function that will encode a transaction as described by
  the input schema.  The generated function is printed to stdout.

  Available options:
    --function-name: specifies the name of the function to generate; if this is
      not specified, the name of the transaction is used
    --input-order: A list of inputs.  Multiple --input-order options can be passed
      and the complete sequence is used to order the input arguments to the
      generated function.  If not specified, the generated ordering is the order
      of inputs as specified in the schema.
    --schema-dir <SCHEMA_DIR>  (default: ./schema)


solxact --find-pda <program_id>

  Reads stdin to acquire seed bytes, then finds a Program Derived Address using
  those seed bytes and the supplied program_id.  Prints out the found address
  and 'bump seed' that was added to the seed bytes as needed to find the
  address, in the form:

    <PROGRAM_DERIVED_ADDRESS>.<BUMP_SEED>


solxact --set-recent-blockhash <OPTIONS>

  Reads a transaction from stdin, acquires a recent blockhash from the cluster, and
  sets the recent blockhash into the transaction, then writes the transaction
  to stdout.  Note that this will invalidate any previous signature applied to
  the transaction.  The transaction will need to be re-signed by all signers.

  Available options:

    -u/--rpc-url: sets the RPC url to use to query for recent blockhash.  The
        following special values may be used:
          -u d  will use a default value for Solana devnet
          -u t  will use a default value for Solana testnet
          -u m  will use a default value for Solana mainnet
        The default RPC url is that of the mainnet default.


solxact --show-unsigned

  Reads a transaction from stdin and prints out to stdout the list of keys
  which are required to sign the transaction but have not yet done so.


solxact --signature

  Reads a transaction from stdin and prints out to stdout the transaction
  signature of the transaction if it is signed.


solxact --sign <private_key>

  Reads a tranasction from stdin and signs it using the supplied private key
  if the key is a signer of the transaction (if the supplied key is not a
  signer of the transaction, the transaction is unaltered).  The resulting
  transaction is printed to stdout.

  <private_key> is either an array of raw bytes, i.e. "[ 1, 2, 3 ... ]"
  or is the path name of a file containing such an array.


solxact --signature-of <public_key>

  Reads a transaction from stdin and prints out to stdout the transaction
  signature applied for the given public_key if it is a signer.


solxact --simulate <OPTIONS>

  Reads a transaction from stdin and submits it for simulation to an RPC
  node, reporting the simulation result.

  Available options:

    -u/--rpc-url: sets the RPC url to use to query for recent blockhash.  The
        following special values may be used:
          -u d  will use a default value for Solana devnet
          -u t  will use a default value for Solana testnet
          -u m  will use a default value for Solana mainnet
        The default RPC url is that of the mainnet default.


solxact --submit <OPTIONS>
  
  Reads a transaction from stdin and submits it for execution to an RPC
  node, reporting the execution result.

  Available options:

    -u/--rpc-url: sets the RPC url to use to query for recent blockhash.  The
        following special values may be used:
          -u d  will use a default value for Solana devnet
          -u t  will use a default value for Solana testnet
          -u m  will use a default value for Solana mainnet
        The default RPC url is that of the mainnet default.
    -w/--wait: wait until the transaction has been finalized before returning
    --skip-preflight: skip preflight transaction checks


solxact --decode <OPTIONS> [schema]

  Reads a transaction from stdin, decodes it, and prints it out in a JSON
  form.  If a schema is provided, it will be used to decode more detailed
  values from transaction; if no schema is provided, but a schema directory
  is present, then it will be searched for program schemas that may match
  instructions within the transaction and additional details will be provided
  for those instructions.

  Available options:

    --schema-dir <SCHEMA_DIR>  (default: ./schema)
    --display <text|json|json_pretty>  Sets the format of the displayed
        output (either text, json, or json_pretty).  Default is json.
```
