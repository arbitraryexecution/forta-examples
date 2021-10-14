const {
  TransactionEvent,
  FindingType,
  FindingSeverity,
  Finding,
} = require('forta-agent');

const { handleTransaction, CONTRACT_ADDRESS, METHOD_ID } = require('./agent');

describe('watch for function call', () => {
  // function for creating a simulated transaction
  const createTxEvent = ({
    to, from, hash, data,
  }) => {
    const type = null;
    const network = null;
    const transaction = {
      to,
      from,
      hash,
      data,
    };
    const receipt = {
    };
    const traces = [];
    const addresses = {};
    const block = {};
    return new TransactionEvent(type, network, transaction, receipt, traces, addresses, block);
  };

  describe('handleTransaction', () => {
    it('returns empty findings if the contract address does not match', async () => {
      const txEvent = createTxEvent({
        to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC (not USDT) contract
        from: '0xab5801a7d398351b8be11c439e05c5b3259aec9b',
        hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
        data: METHOD_ID,
      });

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([]);
    });

    it('returns empty findings if the function signature does not match', async () => {
      const txEvent = createTxEvent({
        to: CONTRACT_ADDRESS,
        from: '0xab5801a7d398351b8be11c439e05c5b3259aec9b',
        hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
        data: '0xdeadbeef',
      });

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([]);
    });

    it('returns a finding if transfer() was called on the target contract', async () => {
      const txEvent = createTxEvent({
        to: CONTRACT_ADDRESS,
        from: '0xab5801a7d398351b8be11c439e05c5b3259aec9b',
        hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
        data: METHOD_ID,
      });

      const findings = await handleTransaction(txEvent);
      const {
        to, from, hash, data,
      } = txEvent.transaction;

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: 'AE-FUNCTION-CALLED',
          description: `transfer() called on USDT contract by ${from}`,
          alertId: 'DEMO-2',
          type: FindingType.Unknown,
          severity: FindingSeverity.Info,
          metadata: {
            from,
            hash,
          },
        }),
      ]);
    });
  });
});
