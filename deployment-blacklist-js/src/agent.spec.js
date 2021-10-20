const {
  TransactionEvent,
  EventType,
  FindingType,
  FindingSeverity,
  Finding,
  Network,
} = require('forta-agent');
const { handleTransaction } = require('./agent');

describe('blacklisted contract deployment', () => {
  // Need to stub out contractAddress and transaction.from
  // function TransactionEvent(type, network, transaction, receipt, traces, addresses, block)
  const createTxEvent = (deployer, contractAddress) => new TransactionEvent(
    EventType.BLOCK, Network.MAINNET, { from: deployer }, { contractAddress }, [], null, null,
  );

  describe('handleTransaction', () => {
    it('returns empty findings if address is not blacklisted', async () => {
      const txEvent = createTxEvent('0x12345', '0x67890');

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([]);
    });

    it('returns a finding if blacklisted address deploys contract', async () => {
      const deployer = '0x099a91d684585618298250cc376a0531f83ef9a2'; // bad guy
      const contractAddress = '0xabcdef';
      const txEvent = createTxEvent(deployer, contractAddress);

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: 'Contract Deployment by Blacklisted Address',
          description: `Deployer: ${txEvent.transaction.from}`,
          alertId: 'AE-BLACKLISTED-ADDRESS-DEPLOYMENT',
          type: FindingType.Suspicious,
          severity: FindingSeverity.Low,
          metadata: { contractAddress },
        }),
      ]);
    });
  });
});
