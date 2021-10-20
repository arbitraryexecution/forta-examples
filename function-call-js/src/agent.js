const { Finding, FindingSeverity, FindingType } = require('forta-agent');

// Monitor the USDT contract for calls to transfer().
// This is a contrived example with a contract and function chosen for the
// ability to quickly do a live test.
const CONTRACT_ADDRESS = '0xdac17f958d2ee523a2206206994597c13d831ec7';
const METHOD_ID = '0xa9059cbb'; // transfer(address _to, uint256 _value)

/**
 * Monitor when a specific function is called on a contract.
 */
async function handleTransaction(txEvent) {
  const findings = [];
  const { from } = txEvent.transaction;

  if ((txEvent.transaction.to === CONTRACT_ADDRESS)
      && (txEvent.transaction.data.startsWith(METHOD_ID))) {
    findings.push(
      Finding.fromObject({
        name: 'USDT Transfer Function Call',
        description: `transfer() called on USDT contract by ${from}`,
        alertId: 'AE-USDT-TRANSFER-FUNC',
        type: FindingType.Info,
        severity: FindingSeverity.Info,
        metadata: {
          from,
        },
      }),
    );
  }

  return findings;
}

module.exports = {
  handleTransaction,
  CONTRACT_ADDRESS,
  METHOD_ID,
};
