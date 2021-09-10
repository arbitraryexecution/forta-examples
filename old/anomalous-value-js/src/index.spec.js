const ethers = require("ethers");
const BigNumber = require("bignumber.js");

const {
  TransactionEvent,
  FindingType,
  FindingSeverity,
  Finding,
} = require("forta-agent");
const { provideHandleTransaction } = require(".");

const oneGwei = new BigNumber(ethers.utils.parseUnits("1", "gwei").toString());

function gwei(numGwei) {
  return oneGwei.times(numGwei);
}

describe("anomolus price agent", () => {
  let handleTransaction;
  const mockProvider = {
    getCode: jest.fn(),
  };

  const createTxEvent = ({ gasPrice }) => {
    const tx = {
      gasPrice,
    };
    return new TransactionEvent(null, null, tx, null, [], {}, null);
  };

  beforeAll(() => {
    handleTransaction = provideHandleTransaction(mockRollingMath);
  });

  describe("handleTransaction", () => {
    const txEvent = createTxEvent({ gasPrice: gwei(30) });

    it("returns empty findings if gasPrice is below threshold", async () => {
      mockRollingMath.getAverage.mockReturnValueOnce(gwei(10));
      mockRollingMath.getStandardDeviation.mockReturnValueOnce(gwei(2));

      const findings = await handleTransaction(txEvent);

      expect(mockRollingMath.getAverage).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.getStandardDeviation).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.addElement).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.addElement).toHaveBeenCalledWith(gwei(30));
      expect(findings).toStrictEqual([]);
    });

    it("returns a finding if volume is above threshold", async () => {
      mockRollingMath.getAverage.mockReset();
      mockRollingMath.getStandardDeviation.mockReset();
      mockRollingMath.addElement.mockReset();

      mockRollingMath.getAverage.mockReturnValueOnce(gwei(10));
      mockRollingMath.getStandardDeviation.mockReturnValueOnce(gwei(1.999999999999));

      const findings = await handleTransaction(txEvent);

      expect(mockRollingMath.getAverage).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.getStandardDeviation).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.addElement).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.addElement).toHaveBeenCalledWith(gwei(30));

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "High Gas Price",
          description: `Gas Price: ${gwei(30)}`,
          alertId: "FORTA-1",
          type: FindingType.Suspicious,
          severity: FindingSeverity.Medium,
        }),
      ]);
    });
  });
});
