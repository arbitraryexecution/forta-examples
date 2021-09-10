const { Finding, FindingSeverity, FindingType } = require('forta-agent');

// TODO: update the blacklist periodically (hourly/daily) by fetching it from an external source

// blacklist.json contains a partial list of actual addresses from the USDT blacklist
// source:  https://dune.xyz/phabc/usdt---banned-addresses
const blacklist = require('./blacklist.json');

/**
 * Monitor all transactions for any that involve a blacklisted address.
 */
async function handleTransaction(txEvent) {
  const findings = [];
  const { from, hash } = txEvent.transaction;

  // look at both EOA and contract addresses
  // ensure all addresses are lowercase for matching
  let addresses = Object.keys(txEvent.addresses);
  addresses = addresses.map((x) => x.toLowerCase());

  for (let i = 0; i < blacklist.usdt_blacklist.length; i++) {
    const address = blacklist.usdt_blacklist[i];
    if (addresses.includes(address)) {
      findings.push(
        Finding.fromObject({
          name: 'Blacklisted Address',
          description: `Blacklisted address ${address} was involved in a transaction`,
          alertId: 'DEMO-3',
          type: FindingType.Suspicious,
          severity: FindingSeverity.Low,
          metadata: {
            from,
            hash,
            address,
          },
        }),
      );
    }
  }

  return findings;
}

module.exports = {
  handleTransaction,
};
