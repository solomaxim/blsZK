const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying contracts with account:", deployer.address);
  console.log("Account balance:", (await deployer.provider.getBalance(deployer.address)).toString());

  // Deploy Verifier
  const Verifier = await ethers.getContractFactory("Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  console.log("Verifier address:", await verifier.getAddress());

  // Deploy ZKRollupBLS
  const ZKRollupBLS = await ethers.getContractFactory("ZKRollupBLS");
  const zkRollup = await ZKRollupBLS.deploy(deployer.address, await verifier.getAddress());
  await zkRollup.waitForDeployment();
  console.log("ZKRollupBLS address:", await zkRollup.getAddress());

  console.log("\nDeployment completed!");
  console.log("Verifier:", await verifier.getAddress());
  console.log("ZKRollupBLS:", await zkRollup.getAddress());
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });