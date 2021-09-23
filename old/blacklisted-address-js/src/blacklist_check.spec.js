const {
  TransactionEvent, FindingType, FindingSeverity, Finding,
} = require('forta-agent');

const { handleTransaction } = require('./blacklist_check');

describe('monitor banned addresses', () => {
  // function for creating a simulated transaction
  const createTxEvent = ({ from, hash, addrs }) => {
    const type = null;
    const network = null;
    const transaction = {
      from,
      hash,
    };
    const receipt = {};
    const traces = [];
    const addresses = addrs;
    const block = {};
    return new TransactionEvent(type, network, transaction, receipt, traces, addresses, block);
  };

  describe('handleTransaction', () => {
    it('returns empty findings if the no addresses match the blacklist', async () => {
      const txEvent = createTxEvent({
        from: '0xab5801a7d398351b8be11c439e05c5b3259aec9b',
        hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
        addrs: {
          '0xab5801a7d398351b8be11c439e05c5b3259aec9b': true,
          '0x0000000000000000000000000000000000000001': true,
          '0x0000000000000000000000000000000000000002': true,
        },
      });

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([]);
    });

    it('returns a finding if any address involved in the transaction is blacklisted', async () => {
      const txEvent = createTxEvent({
        from: '0xab5801a7d398351b8be11c439e05c5b3259aec9b',
        hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
        addrs: {
          '0xab5801a7d398351b8be11c439e05c5b3259aec9b': true,
          '0x0000000000000000000000000000000000000001': true,
          '0x68c88fccbc6d5a218711bd897add734aeefd1270': true,
        },
      });

      const findings = await handleTransaction(txEvent);
      const { from, hash } = txEvent.transaction;
      const address = (findings.length > 0) ? findings[0].metadata.address : undefined;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: 'Blacklisted Address',
          description: `Blacklisted address ${address} was involved in a transaction`,
          alertId: 'AE-BLACKLISTED-USDT',
          type: FindingType.Suspicious,
          severity: FindingSeverity.Low,
          metadata: {
            from,
            hash,
            address,
          },
        }),
      ]);
    });
  });
});
