import json
import pytest
import os

from web3 import Web3

from forta_agent import Finding, FindingSeverity, FindingType, create_transaction_event
from agent import handle_transaction, AttrDict


BURN_ADDR = "0x000000000000000000000000000000000000dEaD"


@pytest.fixture
def alert():
    """
    Various properties of the alert that is raised inside agent.py
    """
    alert_large_swap = Finding(
        {
            "name": "Uniswap V2 swap detector",
            "description": "Large swap on Uniswap V2 detected",
            "alert_id": "AE-UNISWAP-LARGESWAP-EVENT",
            "type": FindingType.Suspicious,
            "severity": FindingSeverity.Low,
        }
    )

    return alert_large_swap

@pytest.fixture
def uniswap_v2_router_addr():
    """
    Load the configureable Uniswap V2 router address.
    """
    dirname = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(dirname, 'config', 'agent-settings.json')

    with open(config_file, 'r') as f:
        data = json.loads(f.read())

    return Web3.toChecksumAddress(data['uniswap_v2_router_addr'])


def check_alerts(expected_alert, found_alert):
    """
    Compares two Finding type objects and asserts that all fields are the same.
    Raises AssertionError if a difference is found between the two alerts
    """
    assert expected_alert.name == found_alert.name
    assert expected_alert.description == found_alert.description
    assert expected_alert.alert_id == found_alert.alert_id
    assert expected_alert.severity.value == found_alert.severity.value
    assert expected_alert.type.value == found_alert.type.value


def gen_tx_data(value="0", from_=BURN_ADDR, to=BURN_ADDR, data="0x"):
    """
    Generate a dict containing transaction data to be used in mocking a transaction
    """
    transaction_data = {}
    transaction_data["value"] = value
    transaction_data["from_"] = from_
    transaction_data["to"] = to
    transaction_data["data"] = data

    return {"transaction": transaction_data}


def gen_tx_receipt(event=None):
    """
    Generate a transaction receipt to be used in creating a mock transaction
    """
    logs = []
    if event == "deposit":
        logs.append(gen_log_receipt("deposit"))

    elif event == "withdrawal":
        logs.append(gen_log_receipt("withdrawal"))

    elif event == "swap":
        logs.append(gen_log_receipt("swap"))

    temp_dict = AttrDict(
        {
            "status": True,
            "root": "",
            "cumulative_gas_used": 0,
            "gas_used": 0,
            "logs_bloom": "0x0",
            "logs": logs,
            "contract_address": None,
            "block_hash": "0x85d8e4f37fd7146d82d3fdb851668ad88eb5351cd535c5fc3d62a40eed817c92",
            "block_number": 13282824,
        }
    )

    return AttrDict({"receipt": temp_dict})


def gen_log_receipt(event):
    """
    Generate a specific log to be used in creating a transaction receipt. These events were
    collected from mainnet. Real data was used as it's cleaner, simpler, and easier to mock
    up to test functionality.
    """
    deposit_event = {
        "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "topics": [
            "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c",
            "0x0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d",
        ],
        "data": "0x0000000000000000000000000000000000000000000000005623309cafe37c00",
        "log_index": 150,
        "block_number": 13282824,
        "block_hash": "0x85d8e4f37fd7146d82d3fdb851668ad88eb5351cd535c5fc3d62a40eed817c92",
        "transaction_index": 136,
        "transaction_hash": "0x0693912717239d8513f4f4af02d401011418381ec0a398d21d6b6dc0bd3d9486",
        "removed": False,
    }

    withdrawal_event = {
        "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "topics": [
            "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65",
            "0x0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d",
        ],
        "data": "0x0000000000000000000000000000000000000000000000007375695a9e01ca7a",
        "log_index": 239,
        "block_number": 13283200,
        "block_hash": "0xf07a5c6d6b1a412a321d21781736d77a39d15024336b9fe2b30dbc666308f550",
        "transaction_index": 202,
        "transaction_hash": "0x1e56a8fc69bae44e22e8de761a08a5d0740348fbe4a0d039262af4545e188614",
        "removed": False,
    }

    swap_event = {
        "address": "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc",
        "topics": [
            "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822",
            "0x0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d",
            "0x0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d",
        ],
        "data": "0x00000000000000000000000000000000000000000000000000000006088fce8e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007375695a9e01ca7a",
        "log_index": 238,
        "block_number": 13283200,
        "block_hash": "0xf07a5c6d6b1a412a321d21781736d77a39d15024336b9fe2b30dbc666308f550",
        "transaction_index": 202,
        "transaction_hash": "0x1e56a8fc69bae44e22e8de761a08a5d0740348fbe4a0d039262af4545e188614",
        "removed": False,
    }

    if event == "deposit":
        return AttrDict(deposit_event)
    elif event == "withdrawal":
        return AttrDict(withdrawal_event)
    elif event == "swap":
        return AttrDict(swap_event)

    return AttrDict({})


def test_transaction_normal(uniswap_v2_router_addr):
    """
    Mock a normal transaction that doesnt emit a Deposit or Withdrawal event
    This should not raise an alert
    """
    tx_dict = gen_tx_data(to=uniswap_v2_router_addr)
    tx_dict.update(gen_tx_receipt())

    tx_event = create_transaction_event(tx_dict)
    findings = handle_transaction(tx_event)

    assert len(findings) == 0


def test_transaction_deposit_event(alert, uniswap_v2_router_addr):
    """
    Mock a transaction that emits a Deposit event
    This will raise an alert
    """
    # Collect the information needed for mocking up a transaction
    tx_dict = gen_tx_data(to=uniswap_v2_router_addr)
    tx_dict.update(gen_tx_receipt(event="deposit"))

    # Generate the mock transaction
    tx_event = create_transaction_event(tx_dict)
    findings = handle_transaction(tx_event)

    assert len(findings) == 1
    check_alerts(alert, findings[0])


def test_transaction_withdraw_event(alert, uniswap_v2_router_addr):
    """
    Mock a transaction that emites a Withdrawal event
    This will raise an alert
    """
    # Collect the information needed for mocking up a transaction
    tx_dict = gen_tx_data(to=uniswap_v2_router_addr)
    tx_dict.update(gen_tx_receipt(event="withdrawal"))

    # Generate the mock transaction
    tx_event = create_transaction_event(tx_dict)
    findings = handle_transaction(tx_event)

    assert len(findings) == 1
    check_alerts(alert, findings[0])
