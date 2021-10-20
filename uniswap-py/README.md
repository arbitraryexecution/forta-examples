# Large Uniswap Detector Agent

## Description

This agent detects large uniswap transactions on ETH liquidity pools

## Supported Chains

- Ethereum

## Alerts

- AE-UNISWAP-LARGESWAP-ETH
  - Fired when a swap occurs where the value being traded is over 5 ether
  - Only triggers when either the `swapExactTokensForETH` or `swapExactETHForTokens`
    Functions are called on the Uniswap v2 Router Contract (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d')

## Test Data

The agent behavior can be verified with the following transactions:

- 0x1dfdaefdc0513ec19bac3325f7a823a523ee72a42385a5208a7eec269207331b

The agent behavior can be verified with the following blocks:
- 13225317
