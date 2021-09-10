import pytest

from forta_agent import Finding, FindingSeverity, FindingType, create_transaction_event

from agent import handle_transaction
import malicious_addrs


@pytest.fixture
def mal_addr():
    """
    Just use the first malicious address for testing
    """
    return malicious_addrs.addrs[0]


@pytest.fixture
def alert(mal_addr):
    """
    The alert that should be raised by the agent
    """
    malicious_addr_alert = Finding(
        {
            "name": "Malicious Address Detected",
            "description": "Malicious address is involved with a transaction",
            "alert_id": "AE-MALICIOUS-ADDR",
            "type": FindingType.Suspicious,
            "severity": FindingSeverity.Medium,
            "metadata": {
                "from": mal_addr,
                "to": None,
                "amount": None,
                "malicious_addresses": mal_addr,
            },
        }
    )

    return malicious_addr_alert


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
    Create a benign transaction that shouldn't raise any alerts
    """
    tx_event = create_transaction_event({})

    findings = handle_transaction(tx_event)

    assert len(findings) == 0


def test_malicious_send(alert, mal_addr):
    """
    Create a transaction that should trigger the first alert
    """
    tx_event = create_transaction_event(
        {"transaction": {"from": mal_addr}, "addresses": [mal_addr]}
    )

    findings = handle_transaction(tx_event)

    # Only one alert should have triggered
    assert len(findings) == 1

    finding = findings[0]

    # Check all the properties on the alert
    check_alerts(alert, finding)


def test_malicious_receive(alert, mal_addr):
    """
    Create a transaction that should trigger the second alert
    """
    tx_event = create_transaction_event(
        {"transaction": {"to": mal_addr}, "addresses": [mal_addr]}
    )

    findings = handle_transaction(tx_event)

    # Only one alert should have triggered
    assert len(findings) == 1

    finding = findings[0]

    # Check all the properties on the alert
    check_alerts(alert, finding)


def test_malicious_addr(alert, mal_addr):
    """
    Create a transaction that should trigger the third alert
    """
    tx_event = create_transaction_event({"addresses": [mal_addr]})

    findings = handle_transaction(tx_event)

    # Only one alert should have triggered
    assert len(findings) == 1

    finding = findings[0]

    # Check all the properties on the alert
    check_alerts(alert, finding)
