const ethers = require("ethers");
const BigNumber = require("bignumber.js");
const { Finding, FindingSeverity, FindingType } = require("forta-agent");
const RollingMath = require("rolling-math");

// rolling average over 1000 transactions
const rollingMath = new RollingMath(1000);

function provideHandleTransaction(rollingMath) {
  return async function handleTransaction(txEvent) {
    const findings = [];

    const gasPrice = new BigNumber(txEvent.gasPrice);
    const average = rollingMath.getAverage();
    const standardDeviation = rollingMath.getStandardDeviation();
    // console.log(`gasPrice: ${gasPrice.toString()}, std: ${standardDeviation}, avg: ${average}`);

    // create finding if gas price is over 10 standard deviations above the past 1000 txs
    if (gasPrice.isGreaterThan(average.plus(standardDeviation.times(10)))) {
      findings.push(
        Finding.fromObject({
          name: "High Gas Price",
          description: `Gas Price: ${gasPrice}`,
          alertId: "FORTA-1",//TODO
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
        })
      );
    }

    // update rolling average
    rollingMath.addElement(gasPrice);

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
  handleTransaction: provideHandleTransaction(rollingMath)
}
