const { ethers } = require("hardhat");
const fs = require("fs");

const path = require("path");

async function main() {
  console.log("\n=====================================");
  console.log("ZK-ROLLUP BLS DEPLOYMENT");
  console.log("=====================================\n");

  // Get deployer account
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();

  console.log("Deployment Information:");
  console.log("  Network:", network.name || `Chain ID ${network.chainId}`);
  console.log("  Deployer:", deployer.address);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("  Balance:", ethers.formatEther(balance), "ETH\n");

  // Check if Verifier.sol exists
  const verifierPath = path.join(__dirname, "../circuits/build/Verifier.sol");
  let verifierAddress;

  if (fs.existsSync(verifierPath)) {
    console.log("Found generated Verifier.sol from circuits");

    // Copy Verifier.sol to contracts directory
    const verifierContent = fs.readFileSync(verifierPath, "utf8");
    fs.writeFileSync(
        path.join(__dirname, "../contracts/Verifier.sol"),
        verifierContent
    );

    // Deploy generated Verifier
    console.log("\n[1/2] Deploying Groth16 Verifier...");
    const Verifier = await ethers.getContractFactory("Verifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    verifierAddress = await verifier.getAddress();
    console.log("  Verifier deployed at:", verifierAddress);

  } else {
    console.log("WARNING: Generated Verifier.sol not found");
    console.log("Using mock verifier for testing");

    // Deploy mock verifier
    console.log("\n[1/2] Deploying Mock Verifier...");
    const MockVerifier = await ethers.getContractFactory("MockBLSVerifier");
    const mockVerifier = await MockVerifier.deploy();
    await mockVerifier.waitForDeployment();
    verifierAddress = await mockVerifier.getAddress();
    console.log("  Mock Verifier deployed at:", verifierAddress);
  }

  // Deploy ZKRollupBLS
  console.log("\n[2/2] Deploying ZKRollupBLS...");
  const ZKRollupBLS = await ethers.getContractFactory("ZKRollupBLS");
  const zkRollup = await ZKRollupBLS.deploy(
      deployer.address,  // sequencer
      verifierAddress    // verifier
  );
  await zkRollup.waitForDeployment();
  const zkRollupAddress = await zkRollup.getAddress();
  console.log("  ZKRollupBLS deployed at:", zkRollupAddress);

  // Verify initial state
  console.log("\nVerifying Initial State:");
  const sequencer = await zkRollup.sequencer();
  const verifierContract = await zkRollup.verifier();
  const batchCount = await zkRollup.batchCount();
  const currentStateRoot = await zkRollup.currentStateRoot();

  console.log("  Sequencer:", sequencer);
  console.log("  Verifier:", verifierContract);
  console.log("  Batch Count:", batchCount.toString());
  console.log("  State Root:", currentStateRoot);

  // Save deployment addresses
  const deploymentInfo = {
    network: network.name || `chain-${network.chainId}`,
    chainId: Number(network.chainId),
    contracts: {
      verifier: verifierAddress,
      zkRollupBLS: zkRollupAddress
    },
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    blockNumber: await ethers.provider.getBlockNumber()
  };

  const deploymentsDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentFile = path.join(
      deploymentsDir,
      `${deploymentInfo.network}.json`
  );

  fs.writeFileSync(
      deploymentFile,
      JSON.stringify(deploymentInfo, null, 2)
  );

  console.log("\nDeployment info saved to:", deploymentFile);

  // Gas usage report
  console.log("\nGas Usage Report:");
  try {
    const sampleMessageHashes = [
      ethers.keccak256(ethers.toUtf8Bytes("test1")),
      ethers.keccak256(ethers.toUtf8Bytes("test2"))
    ];
    const samplePublicKeysX = [BigInt(123), BigInt(456)];
    const samplePublicKeysY = [BigInt(789), BigInt(101112)];
    const sampleProof = new Uint8Array(256);

    const estimatedGas = await zkRollup.submitBatchWithProof.estimateGas(
        ethers.keccak256(ethers.toUtf8Bytes("newState")),
        sampleMessageHashes,
        samplePublicKeysX,
        samplePublicKeysY,
        sampleProof
    );

    console.log("  Estimated gas for 2-signature batch:", estimatedGas.toString());
    console.log("  Gas per signature:", (Number(estimatedGas) / 2).toFixed(0));

    // Compare with traditional BLS
    const traditionalBLSGas = 2 * 300000; // ~300k per BLS verification
    const savings = traditionalBLSGas - Number(estimatedGas);
    const savingsPercent = (savings / traditionalBLSGas * 100).toFixed(1);

    console.log("\nComparison with Traditional BLS:");
    console.log("  Traditional (on-chain):", traditionalBLSGas, "gas");
    console.log("  ZK Rollup:", estimatedGas.toString(), "gas");
    console.log("  Savings:", savings, `gas (${savingsPercent}%)`);
  } catch (error) {
    console.log("  Could not estimate gas:", error.message);
  }

  console.log("\n=====================================");
  console.log("DEPLOYMENT COMPLETED SUCCESSFULLY");
  console.log("=====================================\n");

  return {
    verifier: verifierAddress,
    zkRollupBLS: zkRollupAddress
  };
}

// Execute deployment
main()
    .then((addresses) => {
      console.log("Deployed addresses:", addresses);
      process.exit(0);
    })
    .catch((error) => {
      console.error("\nDeployment failed:", error);
      process.exit(1);
    });