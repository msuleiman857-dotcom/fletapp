from eth_account import Account
from web3 import Web3

BASE_RPC = "https://mainnet.base.org"
USDT_BASE_ADDRESS = "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"  # USDT on Base

ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    },
]

import requests

def get_eth_price_usd() -> float:
    try:
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {"ids": "ethereum", "vs_currencies": "usd"}
        response = requests.get(url, params=params, timeout=5)
        data = response.json()
        return float(data["ethereum"]["usd"])
    except Exception as e:
        print("Error fetching ETH price:", e)
        return 0.0

w3 = Web3(Web3.HTTPProvider(BASE_RPC))


def get_address_from_private_key(private_key: str) -> str:
    if not private_key.startswith("0x"):
        private_key = "0x" + private_key
    account = Account.from_key(private_key)
    return account.address


def get_usdt_balance(wallet_address: str) -> float:
    try:
        token = w3.eth.contract(
            address=Web3.to_checksum_address(USDT_BASE_ADDRESS),
            abi=ERC20_ABI
        )
        balance = token.functions.balanceOf(Web3.to_checksum_address(wallet_address)).call()
        decimals = token.functions.decimals().call()
        return balance / (10 ** decimals)
    except Exception as e:
        print("Error fetching USDT balance:", e)
        return 0.0

def get_eth_balance(wallet_address: str) -> float:
    try:
        balance_wei = w3.eth.get_balance(Web3.to_checksum_address(wallet_address))
        return balance_wei / 10**18
    except Exception as e:
        print("Error fetching ETH balance:", e)
        return 0.0
