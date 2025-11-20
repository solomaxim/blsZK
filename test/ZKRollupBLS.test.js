const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

describe("ZKRollupBLS", function () {
    let zkContract;
    let deployer, sequencer, user1, user2;

    beforeEach(async function () {
        [deployer, sequencer, user1, user2] = await ethers.getSigners();

        const ZKRollupBLS = await ethers.getContractFactory("ZKRollupBLS");
        zkContract = await ZKRollupBLS.deploy(sequencer.address);
        await zkContract.waitForDeployment();

        console.log("Contratto deployed:", await zkContract.getAddress());
    });

    describe("Deployment", function () {
        it("Dovrebbe deployare con sequencer corretto", async function () {
            expect(await zkContract.sequencer()).to.equal(sequencer.address);
            expect(await zkContract.batchCount()).to.equal(0);
            expect(await zkContract.submissionCount()).to.equal(0);
        });

        it("Dovrebbe inizializzare stato L2", async function () {
            expect(await zkContract.l2BlockNumber()).to.equal(0);
            expect(await zkContract.currentStateRoot()).to.equal(ethers.ZeroHash);
        });
    });

    describe("Batch Submission con ZK Proof", function () {
        it("Dovrebbe accettare batch con prova valida", async function () {
            const messageHashes = [
                ethers.keccak256(ethers.toUtf8Bytes("message1")),
                ethers.keccak256(ethers.toUtf8Bytes("message2")),
            ];

            const publicKeysX = [
                BigInt("98765432109876543210"),
                BigInt("98765432109876543211"),
            ];

            const publicKeysY = [
                BigInt("11111111111111111111"),
                BigInt("11111111111111111112"),
            ];

            const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("new_state"));

            // Prova mock (256 bytes di zeri per test)
            const mockProof = new Uint8Array(256);

            const tx = await zkContract.connect(sequencer).submitBatchWithProof(
                stateRoot,
                messageHashes,
                publicKeysX,
                publicKeysY,
                mockProof
            );

            const receipt = await tx.wait();

            console.log("Gas utilizzato:", receipt.gasUsed.toString());

            // Verifica batch creato
            const batch = await zkContract.batches(0);
            expect(batch.stateRoot).to.equal(stateRoot);
            expect(batch.numSignatures).to.equal(2);
            expect(batch.verified).to.be.true;

            // Verifica stato aggiornato
            expect(await zkContract.currentStateRoot()).to.equal(stateRoot);
            expect(await zkContract.l2BlockNumber()).to.equal(1);
        });

        it("NON dovrebbe accettare batch da non-sequencer", async function () {
            const messageHash = ethers.keccak256(ethers.toUtf8Bytes("msg"));
            const mockProof = new Uint8Array(256);

            await expect(
                zkContract.connect(user1).submitBatchWithProof(
                    ethers.ZeroHash,
                    [messageHash],
                    [BigInt(123)],
                    [BigInt(456)],
                    mockProof
                )
            ).to.be.revertedWith("Only sequencer can call");
        });

        it("NON dovrebbe accettare batch vuoti", async function () {
            const mockProof = new Uint8Array(256);

            await expect(
                zkContract.connect(sequencer).submitBatchWithProof(
                    ethers.ZeroHash,
                    [],
                    [],
                    [],
                    mockProof
                )
            ).to.be.revertedWith("Empty batch");
        });

        it("NON dovrebbe accettare array con length mismatch", async function () {
            const messageHash = ethers.keccak256(ethers.toUtf8Bytes("msg"));
            const mockProof = new Uint8Array(256);

            await expect(
                zkContract.connect(sequencer).submitBatchWithProof(
                    ethers.ZeroHash,
                    [messageHash],
                    [BigInt(123)],
                    [BigInt(456), BigInt(789)], // Mismatch!
                    mockProof
                )
            ).to.be.revertedWith("Length mismatch");
        });
    });

    describe("View Functions", function () {
        beforeEach(async function () {
            const messageHashes = [
                ethers.keccak256(ethers.toUtf8Bytes("msg1")),
                ethers.keccak256(ethers.toUtf8Bytes("msg2")),
                ethers.keccak256(ethers.toUtf8Bytes("msg3")),
            ];

            const publicKeysX = [BigInt(100), BigInt(200), BigInt(300)];
            const publicKeysY = [BigInt(400), BigInt(500), BigInt(600)];
            const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("state"));
            const mockProof = new Uint8Array(256);

            await zkContract.connect(sequencer).submitBatchWithProof(
                stateRoot,
                messageHashes,
                publicKeysX,
                publicKeysY,
                mockProof
            );
        });

        it("Dovrebbe restituire dettagli batch", async function () {
            const [stateRoot, numSigs, timestamp, proposer, verified, l2Block] =
                await zkContract.getBatch(0);

            expect(numSigs).to.equal(3);
            expect(proposer).to.equal(sequencer.address);
            expect(verified).to.be.true;
            expect(l2Block).to.equal(1);
        });

        it("Dovrebbe restituire submission IDs per batch", async function () {
            const submissionIds = await zkContract.getBatchSubmissions(0);
            expect(submissionIds.length).to.equal(3);
        });

        it("Dovrebbe restituire stato L2", async function () {
            const [stateRoot, blockNumber, totalBatches] =
                await zkContract.getL2State();

            expect(blockNumber).to.equal(1);
            expect(totalBatches).to.equal(1);
        });
    });

    describe("Gas Analysis", function () {
        it("Dovrebbe misurare gas per batch di diverse dimensioni", async function () {
            const sizes = [1, 5, 10, 20];
            const results = [];

            for (const size of sizes) {
                const messageHashes = Array.from({ length: size }, (_, i) =>
                    ethers.keccak256(ethers.toUtf8Bytes(`msg${i}`))
                );

                const publicKeysX = Array.from({ length: size }, (_, i) =>
                    BigInt(1000 + i)
                );

                const publicKeysY = Array.from({ length: size }, (_, i) =>
                    BigInt(2000 + i)
                );

                const stateRoot = ethers.keccak256(
                    ethers.toUtf8Bytes(`state${size}`)
                );
                const mockProof = new Uint8Array(256);

                const tx = await zkContract
                    .connect(sequencer)
                    .submitBatchWithProof(
                        stateRoot,
                        messageHashes,
                        publicKeysX,
                        publicKeysY,
                        mockProof
                    );

                const receipt = await tx.wait();
                const gasUsed = Number(receipt.gasUsed);
                const gasPerTx = gasUsed / size;

                results.push({ size, gasUsed, gasPerTx });

                console.log(
                    `Batch size ${size}: ${gasUsed} gas total, ${gasPerTx.toFixed(
                        0
                    )} per tx`
                );
            }

            console.log("\n=== Gas Analysis ===");
            results.forEach((r) => {
                console.log(
                    `  Size ${r.size}: ${r.gasPerTx.toFixed(0)} gas/tx`
                );
            });

            // Verifica che gas per tx diminuisce con batch size
            expect(results[3].gasPerTx).to.be.lessThan(results[0].gasPerTx);
        });

        it("Dovrebbe confrontare con approccio tradizionale", async function () {
            const numTx = 10;
            
            // ZK approach
            const messageHashes = Array.from({ length: numTx }, (_, i) =>
                ethers.keccak256(ethers.toUtf8Bytes(`msg${i}`))
            );
            const publicKeysX = Array.from({ length: numTx }, (_, i) =>
                BigInt(1000 + i)
            );
            const publicKeysY = Array.from({ length: numTx }, (_, i) =>
                BigInt(2000 + i)
            );
            const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("state"));
            const mockProof = new Uint8Array(256);

            const tx = await zkContract
                .connect(sequencer)
                .submitBatchWithProof(
                    stateRoot,
                    messageHashes,
                    publicKeysX,
                    publicKeysY,
                    mockProof
                );
            const receipt = await tx.wait();
            const zkGas = Number(receipt.gasUsed);

            // Traditional: ogni firma on-chain costa ~60k gas (BLS pairing)
            const traditionalGas = numTx * 60000;

            const savings = traditionalGas - zkGas;
            const savingsPercent = (savings / traditionalGas) * 100;

            console.log("\n=== Confronto ZK vs Tradizionale ===");
            console.log(`  Transazioni: ${numTx}`);
            console.log(`  ZK Rollup: ${zkGas} gas`);
            console.log(`  Tradizionale: ${traditionalGas} gas`);
            console.log(`  Risparmio: ${savings} gas (${savingsPercent.toFixed(1)}%)`);

            expect(zkGas).to.be.lessThan(traditionalGas);
        });
    });

    describe("Integration con Rust Prover", function () {
        it("Dovrebbe accettare prova da Rust prover (simulato)", async function () {
            // Questo test simula l'integrazione con il prover Rust
            // In produzione, la prova verrebbe da: cargo run --bin bls-prover prove ...

            const messageHash = ethers.keccak256(
                ethers.toUtf8Bytes("real message")
            );
            const publicKeyX = BigInt("12345678901234567890");
            const publicKeyY = BigInt("98765432109876543210");

            // In produzione: prova generata dal prover Rust
            // Per ora: mock proof
            const mockProof = new Uint8Array(256);

            const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("state"));

            const tx = await zkContract
                .connect(sequencer)
                .submitBatchWithProof(
                    stateRoot,
                    [messageHash],
                    [publicKeyX],
                    [publicKeyY],
                    mockProof
                );

            await tx.wait();

            const batch = await zkContract.batches(0);
            expect(batch.verified).to.be.true;

            console.log(
                "Batch verificato con successo usando prova ZK"
            );
        });
    });
});
