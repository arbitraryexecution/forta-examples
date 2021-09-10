import requests

from forta_agent import Finding, FindingType, FindingSeverity
from web3 import Web3

# Swap Eth for DAI
# Value of the tx is 5
# Uniswap v2: Router 2
# 0x7a250d5630b4cf539739df2c5dacb4c659f2488d

# Test cases: 
#   - ETH -> SRM tx hash: 0x315b863c34188c3c8ca399e00d59fe57ce19583eaa053e3df42caa3167a616fe
#   - UFO -> ETH tx hash: 0xf411bd59818d7e07c3da4de2c5d9f62a3e86e1ad5bc994dcefc7e97a9dcdb7ac

ROUTER_ADDR = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d'
ETHER_THRESHOLD = Web3.toWei('.1', 'ether')

# When ppl are swapping token x for ETH you can see this by
# looking at the address and checking the function signature to see which function
# is being called (first 4 bytes)
#   - (0x18cbafe5) swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)
#   - (0x7ff36ab5) swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)

def get_contract_abi(addr):
    """
    Given the address of a smart contract, return the abi provided by etherscan as a string
    """
    url = f'https://api.etherscan.io/api?module=contract&action=getabi&address={addr}'
    resp = requests.get(url)
    resp.raise_for_status()

    return resp.json()['result']


def get_contract_instance(addr):

    abi = get_contract_abi(addr)
    w3 = Web3()
    contract = w3.eth.contract(abi=abi)

    return contract


def handle_transaction(transaction_event):


    swap_token_eth_method = '0x18cbafe5'
    swap_eth_token_method = '0x7ff36ab5'

    if transaction_event.transaction.to != '0x7a250d5630b4cf539739df2c5dacb4c659f2488d':
        return []

    # Length of data must be at least of length 10
    # '0x' is 2 characters and then 8 characters (4 bytes) for the method id
    # Ex: 0x11223344
    if len(transaction_event.transaction.data) < 10:
        return []

    method_id = transaction_event.transaction.data[:10]
    # Check to see if the method id is one of the two we want to check
    if method_id not in [swap_token_eth_method, swap_eth_token_method]:
        return []

    # If the method being called is swapExactETHForTokens, check the value of ETH being sent
    if method_id == swap_eth_token_method:
        value_wei = transaction_event.transaction.value
    else:
        input_data = transaction_event.transaction.data

        func_args = CONTRACT.decode_function_input(input_data)[1]
        value_wei = func_args['amountOutMin']

    if value_wei < ETHER_THRESHOLD:
        return []

    # Send alert
    alert = Finding(
        {
            "name": "Uniswap swap detector",
            "description": "Large swap on Uniswap detected",
            "alert_id": "AE-UNISWAP",
            "type": FindingType.Suspicious,
            "severity": FindingSeverity.Medium,
            "metadata": {
                "from": transaction_event.transaction.from_,
                "to": transaction_event.transaction.to,
                "amount": value_wei
            },
        }
    )

    return [alert]



CONTRACT = get_contract_instance(ROUTER_ADDR)
