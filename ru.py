# send_usdt.py
from web3 import Web3
from get_details import get_address_from_private_key, get_usdt_balance

BASE_RPC = "https://mainnet.base.org"
USDT_CONTRACT = "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"

ERC20_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function"
    }
]

w3 = Web3(Web3.HTTPProvider(BASE_RPC))


def send_usdt(private_key: str, to_address: str, amount: float):
    try:
        from_address = get_address_from_private_key(private_key)
        contract = w3.eth.contract(address=Web3.to_checksum_address(USDT_CONTRACT), abi=ERC20_ABI)

        amount_units = int(amount * 10**6)

        balance = get_usdt_balance(from_address)
        if balance < amount:
            return {"success": False, "error": "Low USDT balance"}

        nonce = w3.eth.get_transaction_count(from_address)
        gas_price = w3.eth.gas_price
        gas_limit = 60000

        tx = contract.functions.transfer(to_address, amount_units).build_transaction({
            "from": from_address,
            "nonce": nonce,
            "gas": gas_limit,
            "gasPrice": gas_price
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if receipt.status == 1:
            return {
                "success": True,
                "tx_hash": w3.to_hex(tx_hash)
            }
        else:
            return {"success": False, "error": "Transaction failed"}

    except Exception as e:
        return {"success": False, "error": str(e)}
