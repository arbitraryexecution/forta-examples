# Function Call Agent

## Description

This agent detects transfer calls on the USDT contract. It serves as an example of how to monitor any contract for any function call.

## Supported Chains

- Ethereum

## Alerts

- AE-FUNCTION-CALLED
  - Fired when the transfer() function is called on the USDT contract
  - Finding type is always set to "unknown"
  - Severity is always set to "low"