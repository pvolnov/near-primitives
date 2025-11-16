
[![PyPI version](https://badge.fury.io/py/pyonear.svg)](https://badge.fury.io/py/pyonear)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/kevinheavey/pyonear/blob/maim/LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# near primitives

A wrapper over `py-near-primitives` rust lib for python. Using for [py-near](https://github.com/pvolnov/py-near).

Latest supported version: `py-near-primitives = "0.2.12"`

**Note:** This library uses Transaction V0 format (priority_fee is not supported).

# use with python 

Use the `py-near` for the high-level api over `py-near-primitives`

Documentation: https://py-near.readthedocs.io/en/latest


## Installation

```
pip install py-near-primitives
```

## Examples

### Example 1: Create and sign a Transfer transaction

```python
import base64
import base58
from nacl import signing, encoding
from py_near_primitives import Transaction, TransferAction

# Prepare transaction data
account_id = "sender.near"
receiver_id = "receiver.near"
nonce = 1
block_hash = base58.b58decode("your_block_hash_here")  # 32 bytes

# Decode private key
private_key_str = "ed25519:your_private_key_here"
pk = base58.b58decode(private_key_str.replace("ed25519:", ""))
private_key = signing.SigningKey(pk[:32], encoder=encoding.RawEncoder)

# Create transfer action (amount in yoctoNEAR)
transfer_action = TransferAction(deposit=1_000_000_000_000_000_000_000_000)  # 1 NEAR

# Create transaction
transaction = Transaction(
    account_id,
    private_key.verify_key.encode(),  # public key (32 bytes)
    nonce,
    receiver_id,
    block_hash,
    [transfer_action],
)

# Sign and serialize
signed_trx = bytes(bytearray(transaction.to_vec(pk)))
base64_tx = base64.b64encode(signed_trx).decode("utf-8")
print(f"Signed transaction: {base64_tx}")
```

### Example 2: Create a FunctionCall transaction

```python
import base64
import base58
import json
from nacl import signing, encoding
from py_near_primitives import Transaction, FunctionCallAction

# Prepare transaction data
account_id = "sender.near"
contract_id = "contract.near"
nonce = 2
block_hash = base58.b58decode("your_block_hash_here")

# Decode private key
private_key_str = "ed25519:your_private_key_here"
pk = base58.b58decode(private_key_str.replace("ed25519:", ""))
private_key = signing.SigningKey(pk[:32], encoder=encoding.RawEncoder)

# Prepare function call arguments
method_name = "set_greeting"
args = json.dumps({"message": "Hello, NEAR!"}).encode()

# Create function call action
function_call = FunctionCallAction(
    method_name=method_name,
    args=args,
    gas=30_000_000_000_000,  # 30 TGas
    deposit=0,  # No deposit
)

# Create and sign transaction
transaction = Transaction(
    account_id,
    private_key.verify_key.encode(),
    nonce,
    contract_id,
    block_hash,
    [function_call],
)

signed_trx = bytes(bytearray(transaction.to_vec(pk)))
base64_tx = base64.b64encode(signed_trx).decode("utf-8")
print(f"Signed transaction: {base64_tx}")
```

### Example 3: Add access key with function call permissions

```python
import base64
import base58
from nacl import signing, encoding
from py_near_primitives import (
    Transaction,
    AddKeyAction,
    AccessKey,
    FunctionCallPermission,
)

# Prepare transaction data
account_id = "sender.near"
nonce = 3
block_hash = base58.b58decode("your_block_hash_here")

# Decode keys
private_key_str = "ed25519:your_private_key_here"
pk = base58.b58decode(private_key_str.replace("ed25519:", ""))
private_key = signing.SigningKey(pk[:32], encoder=encoding.RawEncoder)

# Public key to add (32 bytes)
new_public_key = base58.b58decode("ed25519:new_public_key_here".replace("ed25519:", ""))

# Create function call permission
permission = FunctionCallPermission(
    receiver_id="contract.near",
    method_names=["method1", "method2"],
    allowance=10_000_000_000_000_000_000_000_000,  # 10 NEAR allowance
)

# Create add key action
add_key_action = AddKeyAction(
    public_key=new_public_key,
    access_key=AccessKey(nonce=0, permission=permission),
)

# Create and sign transaction
transaction = Transaction(
    account_id,
    private_key.verify_key.encode(),
    nonce,
    account_id,  # Adding key to own account
    block_hash,
    [add_key_action],
)

signed_trx = bytes(bytearray(transaction.to_vec(pk)))
base64_tx = base64.b64encode(signed_trx).decode("utf-8")
print(f"Signed transaction: {base64_tx}")
```

