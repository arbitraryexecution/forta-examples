const ethers = require("ethers");
const {
  TransactionEvent,
  FindingType,
  FindingSeverity,
  Finding,
} = require("forta-agent");
const { handleTransaction } = require("./agent");

describe("high transaction value agent", () => {
  const createTxEvent = ({ transaction }) => {
    
    return new TransactionEvent(null, null, transaction, {}, [], {}, null);
  };

  describe("handleTransaction", () => {
    it("returns empty findings if value is below threshold", async () => {
      const value = ethers.utils.parseEther("99");

      const txEvent = createTxEvent({
          transaction: {value: value.toString()},
      });

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([]);
    });

    it("returns a finding if gas used is above threshold", async () => {
      const value = ethers.utils.parseEther("701");
      const txEvent = createTxEvent({
        transaction: {value: value.toString()},
      });

      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "High Transaction Value",
          description: `Value: ${ethers.utils.formatEther(value)}`,
          alertId: "AE-BIG-TX",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
        }),
      ]);
    });
  });
});
