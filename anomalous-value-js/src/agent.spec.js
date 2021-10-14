const ethers = require("ethers");
const BigNumber = require("bignumber.js");
const RollingMath = require("rolling-math");

const {
  TransactionEvent,
  FindingType,
  FindingSeverity,
  Finding,
  getJsonRpcUrl
} = require("forta-agent");
const { provideHandleTransaction } = require("./agent");
const provider = new ethers.providers.getDefaultProvider(getJsonRpcUrl());

const oneGwei = new BigNumber(ethers.utils.parseUnits("1", "gwei").toString());

function gwei(numGwei) {
  return oneGwei.times(numGwei);
}

describe("anomalous value agent", () => {
  let handleTransaction;

  const mockRollingMath = {
    getAverage: jest.fn(),
    getStandardDeviation: jest.fn(),
    addElement: jest.fn(),
    getNumElements: jest.fn()
  };
  
  const createTxEvent = (to, value) => {
    const type = null;
    const network = null;
    const transaction = {
      to: to,
      value: value
    };
    const receipt = {};
    const traces = [];
    const addresses = [];
    const block = {};
    return new TransactionEvent(type, network, transaction, receipt, traces, addresses, block);
  };

  //initialize a test address ready for mock RollingMath statistics
  const testAddress = '0x1234';
  let contractAddresses = {};
  contractAddresses[testAddress] = mockRollingMath;

  beforeAll(() => {
    handleTransaction = provideHandleTransaction(contractAddresses, provider);
  });

  describe("handleTransaction", () => {

    it("returns empty findings if there is no 'to' field, as in contract creation", async () => {
      const txEvent = createTxEvent(null, 10);
      const findings = await handleTransaction(txEvent);
      
      expect(findings).toStrictEqual([]);
    });

    it("returns empty findings and adds to contractAddresses if this is the first time seeing a contract", async() => {
      const testContractAddress = '0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9' //Aave token address, need a random contract not in 'contractAddresses'
      
      const txEvent = createTxEvent(testContractAddress, 10);
      const findings = await handleTransaction(txEvent);
      
      expect(findings).toStrictEqual([]);
    });

    it("returns empty findings if 'to' field is an EOA", async() => {
      const testEOA = '0x4683e61663D1dF94340D09E3Ed92D7B05aF2FdB0';

      const txEvent = createTxEvent(testEOA, 10);
      const findings = await handleTransaction(txEvent);

      expect(findings).toStrictEqual([]);
    });

    it("returns empty findings if the value field is within tolerance", async() => {
      mockRollingMath.getAverage.mockReturnValueOnce(gwei(10));
      mockRollingMath.getStandardDeviation.mockReturnValueOnce(gwei(1));
      mockRollingMath.getNumElements.mockReturnValueOnce(41);

      const value = gwei(11);
      const txEvent = createTxEvent(testAddress, value);

      const findings = await handleTransaction(txEvent);

      expect(mockRollingMath.getAverage).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.getStandardDeviation).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.getNumElements).toHaveBeenCalledTimes(0);

      expect(findings).toStrictEqual([]);
    });

    it("returns a finding if the value field is outside tolerance", async() => {
      mockRollingMath.getAverage.mockReset();
      mockRollingMath.getStandardDeviation.mockReset(); 
      mockRollingMath.getNumElements.mockReset(); 

      mockRollingMath.getAverage.mockReturnValueOnce(gwei(10));
      mockRollingMath.getStandardDeviation.mockReturnValueOnce(gwei(1));
      mockRollingMath.getNumElements.mockReturnValueOnce(41);

      const value = gwei(20);
      const txEvent = createTxEvent(testAddress, value);

      const findings = await handleTransaction(txEvent);

      expect(mockRollingMath.getAverage).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.getStandardDeviation).toHaveBeenCalledTimes(1);
      expect(mockRollingMath.getNumElements).toHaveBeenCalledTimes(1);
      
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Abnormally High Value Transaction",
          description: `Value: ${value}`,
          alertId: "AE-ANOMALOUS-VALUE",
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: { "contract" : testAddress },
        }),
      ]);
    })
  });
});
