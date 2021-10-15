const {
  TransactionEvent, FindingType, FindingSeverity, Finding,
} = require('forta-agent');
const ethers = require('ethers');
const { handleTransaction } = require('./agent');
const abi = require('./events.json'); // same list as used in agent script

const contractEvents = abi.map((ourEvent) => `${ourEvent.name}(${
  ourEvent.inputs.map((input) => input.type).join(',')})`);

describe('monitor transfer of ownership', () => {
  // function for creating a simulated transaction
  const createTxEvent = (event) => {
    const type = null;
    const network = null;
    const transaction = {};
    const receipt = {
      logs: [{
        topics: [
          ethers.utils.keccak256(ethers.utils.toUtf8Bytes(event)),
        ],
      }],
    };
    const traces = [];
    const addresses = [];
    const block = {};
    return new TransactionEvent(type, network, transaction, receipt, traces, addresses, block);
  };

  describe('handleTransaction', () => {
    it('returns empty findings if the no events are on the watch list', async () => {
      const txEvent = createTxEvent(ethers.utils.keccak256('0x'));

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([]);
    });

    it('returns a finding if an event was in the watch list', async () => {
      const event = contractEvents[1];
      const txEvent = createTxEvent(event);

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: event.split('(')[0],
          description: event.split('(')[0],
          alertId: 'AE-OWNERSHIP-TRANSFERRED',
          severity: FindingSeverity.Low,
          type: FindingType.Degraded,
        }),
      ]);
    });
  });
});
