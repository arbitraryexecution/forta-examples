# Anomalous Gas Price Agent

## Description

This agent alerts when a transaction pays an atypically large gas price.

## Supported Chains

- Ethereum

## Alerts

- AE-ANOMALOUS-GAS
  - Fires when a transaction uses a gas price that is 10 standard devations over the last 5000 transactions average
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
