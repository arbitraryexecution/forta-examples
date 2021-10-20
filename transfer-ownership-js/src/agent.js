const { Finding, FindingSeverity, FindingType } = require('forta-agent');
const abi = require('./events.json');

const contractEvents = abi.map((ourEvent) => `${ourEvent.name}(${
  ourEvent.inputs.map((input) => input.type).join(',')})`);

const handleTransaction = async (txEvent) => {
  const findings = [];
  let events;

  contractEvents.forEach((eventProto) => {
    events = txEvent.filterEvent(eventProto);
    events.forEach((ourEvent) => {
      if (ourEvent.length !== 0) {
        findings.push(
          Finding.fromObject({
            name: eventProto.split('(')[0], // ex. "OwnershipTransferred"
            description: eventProto.split('(')[0], // ex. "OwnershipTransferred"
            alertId: 'AE-OWNERSHIP-TRANSFERRED',
            severity: FindingSeverity.Low,
            type: FindingType.Degraded,
          }),
        );
      }
    });
  });

  return findings;
};

module.exports = {
  handleTransaction,
};
