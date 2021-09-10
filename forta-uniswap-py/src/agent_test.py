import pytest
from web3 import Web3

from forta_agent import FindingSeverity, FindingType, create_transaction_event
from agent import handle_transaction, get_contract_instance, ROUTER_ADDR


@pytest.fixture
def alert():
    alert_large_swap = Finding(
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


def test_transaction_normal():
    """
    """
    tx_event = create_transaction_event({})
    findings = handle_transaction(tx_event)

    assert len(findings) == 0


def test_transaction_low_value_eth_token():
    """
    """
    tx_event = create_transaction_event(
            {"transaction": {
                "value": Web3.toWei('.01', 'ether'),
                "to": ROUTER_ADDR,
                }
            }
    )
    findings = handle_transaction(tx_event)

    assert len(findings) == 0


def test_transaction_low_value_token_eth():
    # Function prototype:
    # swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)
    args = [Web3.toWei('1', 'ether'), Web3.toWei('.01', 'ether'), [Web3.toChecksumAddress('0xffffffffffffffffffffffffffffffffffffffff'), Web3.toChecksumAddress('0xffffffffffffffffffffffffffffffffffffffff')], ROUTER_ADDR, 1]

    contract = get_contract_instance(ROUTER_ADDR)
    data = contract.encodeABI(fn_name='swapExactTokensForETH', args=args)

    tx_event = create_transaction_event(
            {'transaction': {
                'to': ROUTER_ADDR,
                'data': data,
                }
            })
    findings = handle_transaction(tx_event)

    assert len(findings) == 0


def test_transaction_high_value_eth_token():
    """
    """
    tx_event = create_transaction_event(
            {"transaction": {
                "value": Web3.toWei('100', 'ether'),
                "to": ROUTER_ADDR,
                }
            }
    )
    findings = handle_transaction(tx_event)

    # Only one alert should have triggered
    assert len(findings) == 1

    finding = findings[0]

    # Check all the properties of the alert
    check_alerts(alert, finding)


def test_transaction_high_value_token_eth():
    """
    """
    args = [Web3.toWei('1', 'ether'), Web3.toWei('.01', 'ether'), [Web3.toChecksumAddress('0xffffffffffffffffffffffffffffffffffffffff'), Web3.toChecksumAddress('0xffffffffffffffffffffffffffffffffffffffff')], ROUTER_ADDR, 1]

    contract = get_contract_instance(ROUTER_ADDR)
    data = contract.encodeABI(fn_name='swapExactTokensForETH', args=args)

    tx_event = create_transaction_event(
            {"transaction": {
                "to": ROUTER_ADDR,
                "data": data,
                }
            }
    )
    findings = handle_transaction(tx_event)

    # Only one alert should have triggered
    assert len(findings) == 1

    finding = findings[0]

    # Check all the properties of the alert
    check_alerts(alert, finding)
