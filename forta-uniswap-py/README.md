# High Gas Agent

## Description

This agent detects transactions with high gas consumption

## Supported Chains

- Ethereum
- List any other chains this agent can support e.g. BSC

## Alerts

Describe each of the type of alerts fired by this agent

- FORTA-1
  - Fired when a transaction consumes more gas than 1,000,000 gas
  - Severity is always set to "medium" (mention any conditions where it could be something else)
  - Type is always set to "suspicious" (mention any conditions where it could be something else)
  - Mention any other type of metadata fields included with this alert

## Test Data

The agent behaviour can be verified with the following transactions:

- 0xf411bd59818d7e07c3da4de2c5d9f62a3e86e1ad5bc994dcefc7e97a9dcdb7ac
- 0x315b863c34188c3c8ca399e00d59fe57ce19583eaa053e3df42caa3167a616fe

The agent behaviour can be verified with the following blocks:
- 13191867
- 13191824
