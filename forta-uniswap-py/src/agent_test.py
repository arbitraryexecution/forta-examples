import pytest
from web3 import Web3

from forta_agent import Finding, FindingSeverity, FindingType, create_transaction_event
from agent import handle_transaction, get_contract_instance, ROUTER_ADDR, CONTRACT_INST


BURN_ADDR = "0x000000000000000000000000000000000000dEaD"


@pytest.fixture(scope="session")
def contract():
    """
    This fixture will only query the etherscan API once per session. This bypasses
    the problem of rate limiting when not using an API key
    """
    return get_contract_instance()


@pytest.fixture
def alert():
    """
    Various properties of the alert that is raised inside agent.py
    """
    alert_large_swap = Finding(
        {
            "name": "Uniswap swap detector",
            "description": "Large swap on Uniswap detected",
            "alert_id": "AE-UNISWAP-LARGESWAP-METHODID",
            "type": FindingType.Suspicious,
            "severity": FindingSeverity.Medium,
        }
    )
    return alert_large_swap


def check_alerts(expected_alert, found_alert):
    """
    Compares two Finding type objects and asserts that all fields are the same.
    Raises AssertionError if a difference is found between the two alerts
    """
    assert expected_alert.name == found_alert.name
    assert expected_alert.description == found_alert.description
    assert expected_alert.alert_id == found_alert.alert_id
    assert expected_alert.protocol == found_alert.protocol
    assert expected_alert.severity.value == found_alert.severity.value
    assert expected_alert.type.value == found_alert.type.value
    assert expected_alert.everest_id == found_alert.everest_id


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


def test_transaction_normal(contract):
    """
    Send a benign transaction from one address to another
    This should not raise an alert
    """
    tx_data = gen_tx_data()
    tx_event = create_transaction_event(tx_data)
    findings = handle_transaction(tx_event)

    assert len(findings) == 0


def test_transaction_low_value_eth_token(contract):
    """
    Send a transaction that trades a low amount of ether (.01 ether) for a token
    This should not raise an alert as it is below the treshold
    """
    # Function prototype:
    # swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)
    args = [Web3.toWei("1", "ether"), [BURN_ADDR, BURN_ADDR], ROUTER_ADDR, 1]

    # Encode the function parameters
    data = contract.encodeABI(fn_name="swapExactETHForTokens", args=args)

    # Cast the integer returned by toWei() to a string to avoid an integer parsing bug
    tx_data = gen_tx_data(
        value=str(Web3.toWei(".01", "ether")), to=ROUTER_ADDR, data=data
    )

    # Generate the mock transaction
    tx_event = create_transaction_event(tx_data)
    findings = handle_transaction(tx_event)

    assert len(findings) == 0


def test_transaction_low_value_token_eth(contract):
    """
    Send a transaction that trades a token for a low amount of ether (.01 ether)
    This should not raise an alert as it is below the threshold
    """
    # Function prototype:
    # swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)
    args = [
        Web3.toWei("1", "ether"),
        Web3.toWei(".01", "ether"),
        [BURN_ADDR, BURN_ADDR],
        ROUTER_ADDR,
        1,
    ]

    # Encode the function parameters
    data = contract.encodeABI(fn_name="swapExactTokensForETH", args=args)
    tx_data = gen_tx_data(to=ROUTER_ADDR, data=data)

    # Generate the mock transaction
    tx_event = create_transaction_event(tx_data)
    findings = handle_transaction(tx_event)

    assert len(findings) == 0


def test_transaction_high_value_eth_token(contract, alert):
    """
    Send a transaction that trades a high amount of ether (100 ether) for tokens
    This should raise an alert
    """
    # Function prototype:
    # swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)
    args = [Web3.toWei("1", "ether"), [BURN_ADDR, BURN_ADDR], ROUTER_ADDR, 1]

    # Encode the function parameters
    data = contract.encodeABI(fn_name="swapExactETHForTokens", args=args)

    # Cast the integer returned by toWei() to a string to avoid an integer parsing bug
    tx_data = gen_tx_data(
        value=str(Web3.toWei("100", "ether")), to=ROUTER_ADDR, data=data
    )

    # Generate the mock transaction
    tx_event = create_transaction_event(tx_data)
    findings = handle_transaction(tx_event)

    # Only one alert should have triggered
    assert len(findings) == 1

    finding = findings[0]

    # Checks to ensure the correct alert was raised
    check_alerts(alert, finding)


def test_transaction_high_value_token_eth(contract, alert):
    """
    Send a transaction that trades a token for a high amount of ether (100 ether)
    This should raise an alert
    """
    # Function prototype:
    # swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)
    args = [
        Web3.toWei("1", "ether"),
        Web3.toWei("100", "ether"),
        [BURN_ADDR, BURN_ADDR],
        ROUTER_ADDR,
        1,
    ]

    # Encode the function parameters
    data = contract.encodeABI(fn_name="swapExactTokensForETH", args=args)
    tx_data = gen_tx_data(to=ROUTER_ADDR, data=data)

    # Generate the mock transaction
    tx_event = create_transaction_event(tx_data)
    findings = handle_transaction(tx_event)

    # Only one alert should have triggered
    assert len(findings) == 1

    finding = findings[0]

    # Checks to ensure the correct alert was raised
    check_alerts(alert, finding)
