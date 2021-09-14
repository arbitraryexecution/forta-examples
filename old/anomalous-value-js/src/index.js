const ethers = require("ethers");
const BigNumber = require("bignumber.js");
const RollingMath = require("rolling-math");
const { Finding, FindingSeverity, FindingType, getJsonRpcUrl } = require("forta-agent");

const contractAddresses = {};
const provider = new ethers.providers.getDefaultProvider(getJsonRpcUrl());

function provideHandleTransaction(provider) {
  return async function handleTransaction(txEvent) {
    const findings = [];

    // skip if transaction is contract creation
    if (!txEvent.to) {
      return findings;
    }

    const value = new BigNumber(txEvent.transaction.value);

    // check if we've seen this address
    if (contractAddresses[txEvent.to]) {
      const average = contractAddresses[txEvent.to].getAverage();
      const standardDeviation = contractAddresses[txEvent.to].getStandardDeviation();

      // if the value is over 5 standard deviations from the mean and
      // we have a sample size of more than 40, report the finding
      if (value.isGreaterThan(average.plus(standardDeviation.times(5))) &&
          contractAddresses[txEvent.to].getNumElements() > 40) {
        findings.push(
          Finding.fromObject({
            name: "High Value",
            description: `Value: ${value}`,
            alertId: "AE-ANOMALOUS-VALUE",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: { "contract" : txEvent.to },
          })
        );
      }
    } else {
      if (await provider.getCode(txEvent.to) != "0x") {
        // address is a contract we haven't seen before, initialize it
        contractAddresses[txEvent.to] = new RollingMath(1000);
      } else {
        // externally owned account, return
        return findings;
      }
    }

    // add transaction to contractAddresses dictionary
    contractAddresses[txEvent.to].addElement(value);
    return findings;
  };
}

// const handleBlock = async (blockEvent) => {
//   const findings: Finding[] = [];
//   // detect some block condition
//   return findings;
// };

module.exports = {
  provideHandleTransaction,
  handleTransaction: provideHandleTransaction(provider)
}
