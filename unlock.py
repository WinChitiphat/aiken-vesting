from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    PlutusData,
    PlutusV2Script,
    Redeemer,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
)
from pycardano.hash import (
    VerificationKeyHash,
    TransactionId,
    ScriptHash,
)
import json
import os
import sys

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
 
def unlock(
    utxo: UTxO,
    from_script: PlutusV2Script,
    redeemer: Redeemer,
    signing_key: PaymentSigningKey,
    owner: VerificationKeyHash,
    context: BlockFrostChainContext,
) -> TransactionId:
    # read addresses
    with open("wallets/beneficiary.addr", "r") as f:
        input_address = Address.from_primitive(f.read())
 
    # build transaction
    builder = TransactionBuilder(context=context)
    builder.add_script_input(
        utxo=utxo,
        script=from_script,
        redeemer=redeemer,
    )
    builder.add_input_address(input_address)
    builder.add_output(
        TransactionOutput(
            address=input_address,
            amount=utxo.output.amount.coin,
        )
    )
    builder.required_signers = [owner]
    signed_tx = builder.build_and_sign(
        signing_keys=[signing_key],
        change_address=input_address,
        auto_validity_start_offset=0, # set validity start to current slot
        auto_ttl_offset=2*60*60, # add two hours (TTL: time to live in slots == seconds)
    )
 
    # submit transaction
    return context.submit_tx(signed_tx)
 
def get_utxo_from_str(tx_id: str, contract_address: Address) -> UTxO:
    for utxo in context.utxos(str(contract_address)):
        if str(utxo.input.transaction_id) == tx_id:
            return utxo
    raise Exception(f"UTxO not found for transaction {tx_id}")
 
@dataclass
class HelloWorldRedeemer(PlutusData):
    CONSTR_ID = 0
    msg: bytes
 
context = BlockFrostChainContext(
    project_id=os.environ["BLOCKFROST_PROJECT_ID"],
    base_url="https://cardano-preview.blockfrost.io/api/",
)
 
signing_key = PaymentSigningKey.load("wallets/beneficiary.sk")
 
validator = read_validator()
 
# get utxo to spend
txid = "ba4d4b5bfc965ccb829d5740126925cdec9f37f72fe0291c9c7261ce3b7528c1"
utxo = get_utxo_from_str(txid, Address(
    payment_part = validator["script_hash"],
    network=Network.TESTNET,
))
 
# build redeemer
redeemer = Redeemer(data=HelloWorldRedeemer(msg=b"Hello, World!"))
# redeemer = Redeemer(PlutusData())
 
# execute transaction
tx_hash = unlock(
    utxo=utxo,
    from_script=validator["script_bytes"],
    redeemer=redeemer,
    signing_key=signing_key,
    owner=PaymentVerificationKey.from_signing_key(signing_key).hash(),
    context=context,
)
 
print(
    f"2 tADA unlocked from the contract\n\tTx ID: {tx_hash}\n\tRedeemer: {redeemer.to_cbor_hex()}"
)