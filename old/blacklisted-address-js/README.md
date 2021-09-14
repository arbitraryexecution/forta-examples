# Blacklisted USDT Address Agent

## Description

This agent detects if an address that has been banned by the USDT contract is involved in any transaction.
This is an example agent that contains only a portion of the complete list of 500+ banned addresses.

## Supported Chains

- Ethereum

## Alerts

- AE-BLACKLISTED-USDT
  - Triggered when an address in the blacklist.json file is involved in a transaction
  - Finding type is always set to "suspicious"
  - Finding severity is always set to "low"
