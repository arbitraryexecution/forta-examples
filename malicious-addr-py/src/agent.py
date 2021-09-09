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

    send_alert = Finding(
        {
            "name": "Malicious Address Send",
            "description": "Malicious address is starting a transaction",
            "alert_id": "AE-MALICIOUS-ADDR-1",
            "type": FindingType.Suspicious,
            "severity": FindingSeverity.Info,
            "metadata": {
                "from": transaction_event.transaction.from_,
                "to": transaction_event.transaction.to,
                "amount": transaction_event.transaction.value,
                "hash": transaction_event.transaction.hash,
            },
        }
    )

    receive_alert = Finding(
        {
            "name": "Malicious Address Receive",
            "description": "Malicious address is the target of a transaction",
            "alert_id": "AE-MALICIOUS-ADDR-2",
            "type": FindingType.Suspicious,
            "severity": FindingSeverity.Info,
            "metadata": {
                "from": transaction_event.transaction.from_,
                "to": transaction_event.transaction.to,
                "amount": transaction_event.transaction.value,
                "hash": transaction_event.transaction.hash,
            },
        }
    )

    intermediary_alert = Finding(
        {
            "name": "Malicious Address Intermediary",
            "description": "Malicious address is involved with a transaction",
            "alert_id": "AE-MALICIOUS-ADDR-3",
            "type": FindingType.Suspicious,
            "severity": FindingSeverity.Info,
            "metadata": {
                "from": transaction_event.transaction.from_,
                "to": transaction_event.transaction.to,
                "amount": transaction_event.transaction.value,
                "hash": transaction_event.transaction.hash,
            },
        }
    )

    # If the malicious address is sending the funds, send the first alert
    if transaction_event.transaction.from_ in malicious_addrs.addrs:
        return [send_alert]

    # If the malicious address is receiving the funds, send the second alert
    elif transaction_event.transaction.to in malicious_addrs.addrs:
        return [receive_alert]

    # If the malicious address is involved with the transaction but not the sender or receiver,
    # send the third alert
    elif any(
        True for addr in transaction_event.addresses if addr in malicious_addrs.addrs
    ):
        return [intermediary_alert]

    else:
        raise Exception("Error processing information")
