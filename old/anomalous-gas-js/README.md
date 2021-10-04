# Anomalous Gas Price Agent

## Description

This agent alerts when a transaction pays a large amount per gas.

## Supported Chains

- Ethereum

## Alerts

Describe each of the type of alerts fired by this agent

- AE-ANOMALOUS-GAS
  - fires when a transaction uses a gas price that is 10 standard devations over the last 5000 transactions average
