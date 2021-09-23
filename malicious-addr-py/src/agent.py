from forta_agent import Finding, FindingType, FindingSeverity

from src import malicious_addrs


def handle_transaction(transaction_event):
    """
    Check to see if the malicious address was involved with a transaction.
    Return an empty list if the malicious address is not involved and does not
    trigger an alert
    """
    addresses = transaction_event.addresses

    # If no malicious addresses are involved in the transaction, no alert should be raised
    for addr in addresses:
        if addr in malicious_addrs.addrs:
            break
    else:
        return []

    alerts = []
    bad_addrs = []
    # If the malicious address is involved with the transaction send an alert
    for addr in addresses:
        if addr in malicious_addrs.addrs:
            bad_addrs.append(addr)
    else:
        if bad_addrs:
            alert = Finding(
                {
                    "name": "Malicious Address Detected",
                    "description": "Malicious address is involved with a transaction",
                    "alert_id": "AE-MALICIOUS-ADDR",
                    "type": FindingType.Suspicious,
                    "severity": FindingSeverity.Medium,
                    "metadata": {
                        "from": transaction_event.transaction.from_,
                        "to": transaction_event.transaction.to,
                        "amount": transaction_event.transaction.value,
                        "malicious_addresses": bad_addrs,
                    },
                }
            )
            alerts.append(alert)

    return alerts
