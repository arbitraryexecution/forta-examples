# Function Call Agent

## Description

This agent detects transfer calls on the USDT contract. It serves as an example of how to monitor any contract for any function call.
NOTE:  USDT transfers happen frequently--expect this agent to generate numerous findings every minute.

## Supported Chains

- Ethereum

## Alerts

- AE-USDT-TRANSFER-FUNC
  - Fired when the transfer() function is called on the USDT contract
  - Finding type is always set to "info"
  - Severity is always set to "info"
  - Metadata field contains the from address of the transaction
