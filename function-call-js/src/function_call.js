const { Finding, FindingSeverity, FindingType } = require("forta-agent");

// Monitor the USDT contract for calls to transfer().
// This is a contrived example with a contract and function chosen for the
// ability to quickly do a live test.
const CONTRACT_ADDRESS = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const METHOD_ID = "0xa9059cbb"; // transfer(address _to, uint256 _value)

/**
 * Monitor when a specific function is called on a contract.
 */
async function handleTransaction(txEvent) {
  const findings = [];
  const { to, from, hash, data } = txEvent.transaction;

  if ((txEvent.transaction.to == CONTRACT_ADDRESS) && 
      (txEvent.transaction.data.startsWith(METHOD_ID))) {    
    findings.push(
      Finding.fromObject({
        name: "USDT Transfer",
        description: `transfer() called on USDT contract by ${from}`,
        alertId: "DEMO-2",
        type: FindingType.Unknown,
        severity: FindingSeverity.Info,
        metadata: {
          from,
          hash
        },
      })
    );
  };
 
  return findings;
}

module.exports = {
  handleTransaction,
  CONTRACT_ADDRESS,
  METHOD_ID
};  
