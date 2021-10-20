const ethers = require('ethers');
const { Finding, FindingSeverity, FindingType } = require('forta-agent');

const handleTransaction = async (txEvent) => {
  const findings = [];
  const threshold = ethers.utils.parseUnits('700');

  const txValue = ethers.BigNumber.from(txEvent.transaction.value);
  if (txValue.gt(threshold)) {
    findings.push(
      Finding.fromObject({
        name: 'High Transaction Value',
        description: `Value: ${ethers.utils.formatEther(txValue)}`,
        alertId: 'AE-BIG-TX',
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
      }),
    );
  }

  return findings;
};

module.exports = {
  handleTransaction,
};
