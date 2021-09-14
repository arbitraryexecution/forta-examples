const ethers = require("ethers");
const BigNumber = require("bignumber.js");
const { Finding, FindingSeverity, FindingType, getJsonRpcUrl } = require("forta-agent");

const ABI = require("./events.json");
const EVENTS = ABI.map(ourEvent => ourEvent["name"] + "(" +
  ourEvent["inputs"].map(input => input["type"]).join(",") + ")");

const provider = new ethers.providers.getDefaultProvider(getJsonRpcUrl());

const handleTransaction = async (txEvent) => {
  const findings = [];
  let events;

  EVENTS.forEach(eventProto => {
    events = txEvent.filterEvent(eventProto);
    events.forEach(ourEvent => {
      if (ourEvent.length != 0) {
        findings.push(
          Finding.fromObject({
            name: eventProto.split("(")[0],
            description: eventProto.split("(")[0],
            alertId: "AE-OWNERSHIP-TRANSFERRED",
            severity: FindingSeverity.Low,
            type: FindingType.Degraded,
          })
        );
      }
    });
  });

  return findings;
};

// const handleBlock = async (blockEvent) => {
//   const findings: Finding[] = [];
//   // detect some block condition
//   return findings;
// };

module.exports = {
  handleTransaction,
  // handleBlock,
};
