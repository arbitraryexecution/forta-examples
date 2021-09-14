# Ownership Transfer Agent

## Description

This agent detects the OwnershipTransferred and RoleAdminChanged events on Ownable contracts.

## Supported Chains

- Ethereum

## Alerts

- AE-OWNERSHIP-TRANSFERRED
  - Fired when the RoleAdminChanged or OwnershipTransferred event occurs
  - Finding type is always set to "degraded"
  - Finding severity is always set to "low"
