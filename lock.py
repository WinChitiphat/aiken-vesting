from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    PlutusData,
    PlutusV2Script,
    TransactionBuilder,
    TransactionOutput,
)
from pycardano.hash import (
    VerificationKeyHash,
    TransactionId,
    ScriptHash,
)
import json
import os

@dataclass
class VestingDatum(PlutusData):
    CONSTR_ID = 0
    lock_until: int
    owner: bytes
    beneficiary: bytes
 
os.environ["BLOCKFROST_PROJECT_ID"] = "preview3nu************************"
os.chdir('/home/ubuntu/vesting/')

def read_validator() -> dict:
    with open("plutus.json", "r") as f:
        validator = json.load(f)
    script_bytes = PlutusV2Script(
        bytes.fromhex(validator["validators"][0]["compiledCode"])
    )
    script_hash = ScriptHash(bytes.fromhex(validator["validators"][0]["hash"]))
    return {
        "type": "PlutusV2",
        "script_bytes": script_bytes,
        "script_hash": script_hash,
    }
 
def lock(
    amount: int,
    into: ScriptHash,
    datum: PlutusData,
    signing_key: PaymentSigningKey,
    context: BlockFrostChainContext,
) -> TransactionId:
    # read addresses
    with open("wallets/owner.addr", "r") as f:
        input_address = Address.from_primitive(f.read())
    contract_address = Address(
        payment_part = into,
        network=Network.TESTNET,
    )
 
    # build transaction
    builder = TransactionBuilder(context=context)
    builder.add_input_address(input_address)
    builder.add_output(
        TransactionOutput(
            address=contract_address,
            amount=amount,
            datum=datum,
        )
    )
    signed_tx = builder.build_and_sign(
        signing_keys=[signing_key],
        change_address=input_address,
    )
 
    # submit transaction
    return context.submit_tx(signed_tx)
 
context = BlockFrostChainContext(
    project_id=os.environ["BLOCKFROST_PROJECT_ID"],
    base_url="https://cardano-preview.blockfrost.io/api/",
)
 
signing_key = PaymentSigningKey.load("wallets/owner.sk")
 
validator = read_validator()
 
owner = PaymentVerificationKey.from_signing_key(signing_key).hash()
 
with open("wallets/beneficiary.addr", "r") as f:
    beneficiary_public_key_hash = Address.from_primitive(f.read()).payment_part

datum = VestingDatum(
    lock_until=1698259500000,  #  Wed Jan 04 2023 14:52:41 GMT+0000
    owner=owner.to_primitive(),  # our own wallet verification key hash
    beneficiary=beneficiary_public_key_hash.to_primitive(),
)
 
tx_hash = lock(
    amount=2_000_000,
    into=validator["script_hash"],
    datum=datum,
    signing_key=signing_key,
    context=context,
)
 
print(
    f"2 tADA locked into the contract\n\tTx ID: {tx_hash}\n\tDatum: {datum.to_cbor_hex()}"
)