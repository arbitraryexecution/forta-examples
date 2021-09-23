# Large Uniswap Detector Agent

## Description

This agent detects large uniswap transactions on ETH liquidity pools

## Supported Chains

- Ethereum

## Alerts

- AE-UNISWAP-LARGESWAP-EVENT
  - Fired when a swap occurs where the value being traded is over 5 ether
  - Only triggers when a Deposit or Withdrawal event occurs on the WETH contract via the Uniswap V2
    Router contract

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x0693912717239d8513f4f4af02d401011418381ec0a398d21d6b6dc0bd3d9486
- 0x1e56a8fc69bae44e22e8de761a08a5d0740348fbe4a0d039262af4545e188614

The agent behaviour can be verified with the following blocks:
- 13282824
- 13283200
