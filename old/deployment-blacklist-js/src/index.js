const ethers = require("ethers");
const BigNumber = require("bignumber.js");
const { Finding, FindingSeverity, FindingType, getJsonRpcUrl } = require("forta-agent");

// Maybe get this from a database or JSON file instead?
const BLACKLIST = {
        "0x099a91d684585618298250cc376a0531f83ef9a2": true
}

const handleTransaction = async (txEvent) => {
  const findings = [];
  const contractAddress = txEvent.receipt.contractAddress;
  if (contractAddress != null) {
    // Look and see if the deployer is a bad guy
    const isBlacklisted = BLACKLIST[txEvent.transaction.from];
    if (!isBlacklisted) return findings;
      
    findings.push(
      Finding.fromObject({
        name: "Contract Deployment by Blacklisted Address",
        description: `Deployer: ${txEvent.transaction.from}`,
        alertId: "AE-BLACKLISTED-ADDRESS-DEPLOYMENT",
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
        metadata: { contractAddress: contractAddress}
      })
    );
  }
  return findings;
};

module.exports = {
  handleTransaction,
};
