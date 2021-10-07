# Anomalous Value Agent

## Description

This agent detects transactions that have a large Ether value relative to other current transactions.

## Supported Chains

- Ethereum

## Alerts

- AE-ANOMALOUS-VALUE
  - Fired when the transaction value is over 5 standard deviations from the mean
  - Severity is always set to "medium"
  - Type is always set to "suspicious"

