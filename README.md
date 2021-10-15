# forta-examples
This repo contains several examples of Forta agents that monitor for specific events happening on Ethereum. When the agent discovers an event of interest, a Finding is pushed. Short description of each agent example as follows:

## anomalous-gas-js
Monitors gas spend of transactions and fires an alert when a gas price 10 standard devations over the last 5000 transactions average is used.

## anomalous-value-js
Detects transactions that have a large value relative to other transactions that interact with the same smart contract. Fires when the transaction value is 5 standard deviations above the average.

## big-tx-js
Detects transactions with a value above a specific threshold and fires an alert.

## blacklisted-address-js
Fires an alert when an address on a blacklist transacts.

## deployment-blacklist-js
Fires an alert when a specific (blacklisted) address deploys a contract.

## forta-uniswap-event-py
Fires an alert when a Deposit or Withdrawal event occurs on the WETH contract above the 5 ether threshold limit via the Uniswap V2 Router contract

## forta-uniswap-py
Detects swaps occurring via the `swapExactTokensForETH` or `swapExactETHForTokens` callso n the Uniswap v2 Router contract, fires an alert when above 5 ether.

## function-call-js
This agent detects transfer calls on the USDT contract. It serves as an example of how to monitor any contract for any function call.


## malicious-addr-py
This agent checks transactions against a pre-defined list of addresses that are known to have been involved in public hacks. Fires an alert when the malicious address initiates a transaction.

## transfer-ownership-js
This agent detects the OwnershipTransferred and RoleAdminChanged events on Ownable contracts and fires an alert when they occur.
