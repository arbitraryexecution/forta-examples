# Malicious address detection

## Description

This agent detects transactions that involve a pre-defined malicious address

## Supported Chains

- Ethereum

## Alerts

Describe each of the type of alerts fired by this agent

- AE-MALICIOUS-ADDR-SEND
  - Fired when the malicious address is initiating a transaction
- AE-MALICIOUS-ADDR-RECEIVE
  - Fired when the malicious address is the destination of a transaction
- AE-MALICIOUS-ADDR-INTERMEDIARY
  - Fired when the malicious address is involved in a transaction

## Test Data

The agent behaviour can be verified with the following block:
- block: 13125071

To run unit tests:
- python3 -m pytest -sv
