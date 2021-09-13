# Large Uniswap Detector Agent

## Description

This agent detects large uniswap transactions

## Supported Chains

- Ethereum

## Alerts

Describe each of the type of alerts fired by this agent

- AE-UNISWAP
  - Fired when a swap occurs where the value being traded is over .1 ether
  - Only triggers when either the `swapExactTokensForETH` or `swapExactETHForTokens`
    functions are called on the AAVE v2 Router Contract (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d')

## Test Data

The agent behaviour can be verified with the following transactions:

- 0xf411bd59818d7e07c3da4de2c5d9f62a3e86e1ad5bc994dcefc7e97a9dcdb7ac
- 0x315b863c34188c3c8ca399e00d59fe57ce19583eaa053e3df42caa3167a616fe

The agent behaviour can be verified with the following blocks:
- 13191867
- 13191824
