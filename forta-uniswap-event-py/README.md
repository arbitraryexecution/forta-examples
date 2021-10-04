# Large Uniswap V2 Detector Agent

## Description

This agent detects large Uniswap V2 transactions on ETH liquidity pools.

## Supported Chains

- Ethereum

## Alerts

- AE-UNISWAP-LARGESWAP-EVENT
  - Fired when a Deposit or Withdrawal event occurs on the WETH contract above the 5 ether
    threshold limit via the Uniswap V2 Router contract
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata field contains to and from addresses, as well as the amount of ether

## Test Data

The agent behavior can be verified with the following transactions:

- 0x0693912717239d8513f4f4af02d401011418381ec0a398d21d6b6dc0bd3d9486
- 0x1e56a8fc69bae44e22e8de761a08a5d0740348fbe4a0d039262af4545e188614

The agent behavior can be verified with the following blocks:
- 13282824
- 13283200
