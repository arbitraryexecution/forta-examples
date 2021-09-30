import binascii
import json
import os

from web3 import logs, Web3

from forta_agent import Finding, FindingType, FindingSeverity

UNISWAP_V2_ROUTER_ADDR = None
ETHER_THRESHOLD = None
EVEREST_ID = None
CONTRACT_INST = None


class AttrDict(dict):
    """
    Allows a dictionary to act as a class object and attributes can be retrieved with
    the . "dot" notation or the "['']" square bracket notation. This is a very useful helper
    class since web3 typically uses square bracket notation and forta-agent uses dot syntax
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self


def load_config():
    """
    Load the configuration values from config/agent-settings.json
    """
    global UNISWAP_V2_ROUTER_ADDR
    global ETHER_THRESHOLD
    global EVEREST_ID

    dirname = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(dirname, 'config', 'agent-settings.json')

    with open(config_file, 'r') as f:
        data = json.loads(f.read())

    UNISWAP_V2_ROUTER_ADDR = Web3.toChecksumAddress(data['uniswap_v2_router_addr'])
    ETHER_THRESHOLD = data['ether_threshold']
    EVEREST_ID = data['everest_id']


def get_contract_abi():
    """
    Given the address of a smart contract, return the abi provided by etherscan as a string
    """
    # ABI was retrieved from:
    #   - https://etherscan.io/address/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2#code
    with open("weth_abi.json", "r") as f:
        abi = json.loads(f.read())

    return abi


def get_contract_instance():
    """
    Get an instance of the contract by using the ABI saved in 'router_abi.json`
    This will allow us to encode and decode function parameters
    """
    global CONTRACT_INST
    if CONTRACT_INST:
        return CONTRACT_INST

    abi = get_contract_abi()
    w3 = Web3()
    CONTRACT_INST = w3.eth.contract(abi=abi)
    return CONTRACT_INST


def create_alert(to_addr, from_addr, amount_wad):
    """
    Return an alert with a metadata field that contains
        - to address
        - from address
        - amount in wad
    """
    return Finding(
        {
            "name": "Uniswap V2 swap detector",
            "description": "Large swap on Uniswap V2 detected",
            "alert_id": "AE-UNISWAP-LARGESWAP-EVENT",
            "type": FindingType.Suspicious,
            "severity": FindingSeverity.Low,
            "metadata": {"from": from_addr, "to": to_addr, "amount": amount_wad},
            "everest_id": EVEREST_ID,
        }
    )


def handle_transaction(transaction_event):
    """
    Entry point for a transaction
    """
    input_data = transaction_event.transaction.data
    if not input_data:
        return []

    # Ensure the 'to' field exists (will be a None on contract creation) and that it matches
    # the UNISWAP_V2_ROUTER_ADDR
    if (
        transaction_event.transaction.to
        and Web3.toChecksumAddress(transaction_event.transaction.to) != UNISWAP_V2_ROUTER_ADDR
    ):
        return []

    contract_inst = get_contract_instance()

    attr_logs = []
    for log in transaction_event.receipt.logs:
        # Need to convert the hexadecimal string to binary data for web3
        # Ensure the '0x' is stripped off the beginning of the string before converting
        # Example:
        #   - Convert '0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822'
        #     to b'\xd7\x8a\xd9_\xa4l\x99KeQ\xd0\xda\x85\xfc\'_\xe6\x13\xce7e\x7f\xb8\xd5\xe3\xd10\x84\x01Y\xd8"'
        new_topics = []
        for topic in log.topics:
            new_topics.append(binascii.unhexlify(topic[2:]))
        """
        from types.py inside web3 python module

        class LogReceipt(TypedDict):
            address: ChecksumAddress
            blockHash: HexBytes
            blockNumber: BlockNumber
            data: HexStr
            logIndex: int
            payload: HexBytes
            removed: bool
            topic: HexBytes
            topics: Sequence[HexBytes]
            transactionHash: HexBytes
            transactionIndex: int
        """
        temp_dict = AttrDict(
            {
                "address": Web3.toChecksumAddress(log.address),
                "blockHash": log.block_hash,
                "blockNumber": log.block_number,
                "data": log.data,
                "logIndex": log.log_index,
                "payload": transaction_event.transaction.data,
                "removed": log.removed,
                "topic": new_topics[0],
                "topics": new_topics,
                "transactionHash": log.transaction_hash,
                "transactionIndex": log.transaction_index,
            }
        )
        attr_logs.append(temp_dict)

    """
    from types.py inside web3 python module

    TxReceipt = TypedDict("TxReceipt", {
	"blockHash": HexBytes,
	"blockNumber": BlockNumber,
	"contractAddress": Optional[ChecksumAddress],
	"cumulativeGasUsed": int,
	"effectiveGasPrice": int,
	"gasUsed": Wei,
	"from": ChecksumAddress,
	"logs": List[LogReceipt],
	"logsBloom": HexBytes,
	"root": HexStr,
	"status": int,
	"to": ChecksumAddress,
	"transactionHash": HexBytes,
	"transactionIndex": int,
    })
    """
    tx_receipt = AttrDict(
        {
            "blockHash": transaction_event.receipt.block_hash,
            "blockNumber": transaction_event.receipt.block_number,
            "contractAddress": transaction_event.receipt.contract_address,
            "cumulativeGasUsed": transaction_event.receipt.cumulative_gas_used,
            "effectiveGasPrice": 0,
            "gasUsed": transaction_event.receipt.gas_used,
            "from": transaction_event.transaction.from_,
            "logs": attr_logs,
            "logsBloom": transaction_event.receipt.logs_bloom,
            "root": transaction_event.receipt.root,
            "status": transaction_event.receipt.status,
            "to": transaction_event.transaction.to,
            "transactionHash": transaction_event.receipt.transaction_hash,
            "transactionIndex": transaction_event.receipt.transaction_index,
        }
    )

    deposit_logs = contract_inst.events.Deposit().processReceipt(
        tx_receipt, errors=logs.DISCARD
    )
    withdrawal_logs = contract_inst.events.Withdrawal().processReceipt(
        tx_receipt, errors=logs.DISCARD
    )

    # If no Deposit or Withdrawal events occurred, don't raise any alerts
    if not deposit_logs and not withdrawal_logs:
        return []

    alerts = []
    # Record any Deposit events that are sent to the Uniswap V2 Router address
    # that are above the threshold
    for event in deposit_logs:
        if event["args"]["dst"] == UNISWAP_V2_ROUTER_ADDR:
            if event["args"]["wad"] < ETHER_THRESHOLD:
                continue

            alert = create_alert(
                transaction_event.transaction.to,
                transaction_event.transaction.from_,
                event["args"]["wad"],
            )
            alerts.append(alert)

    # Record any Withdrawal events that are sent from the Uniswap V2 Router address
    # that are above the threshold
    for event in withdrawal_logs:
        if event["args"]["src"] == UNISWAP_V2_ROUTER_ADDR:
            if event["args"]["wad"] < ETHER_THRESHOLD:
                continue

            alert = create_alert(
                transaction_event.transaction.to,
                transaction_event.transaction.from_,
                event["args"]["wad"],
            )
            alerts.append(alert)

    return alerts

load_config()
