// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBLSVerifier.sol";

/**
 * @title ZKRollupBLS
 * @notice ZK Rollup per verifica batch di firme BLS usando Groth16
 * @dev Utilizza un verifier esterno per le prove ZK
 */
contract ZKRollupBLS {
    // ============ STRUCTS ============

    struct Batch {
        bytes32 stateRoot;
        uint32 numSignatures;
        uint64 timestamp;
        address proposer;
        bool verified;
        uint64 l2BlockNumber;
    }

    struct SignatureSubmission {
        bytes32 messageHash;
        uint256 publicKeyX;
        uint256 publicKeyY;
        bool included;
    }

    // ============ STATE VARIABLES ============

    address public immutable sequencer;
    IBLSVerifier public verifier;

    uint256 public batchCount;
    uint256 public submissionCount;
    uint256 public l2BlockNumber;
    bytes32 public currentStateRoot;

    mapping(uint256 => Batch) public batches;
    mapping(uint256 => SignatureSubmission) public submissions;
    mapping(uint256 => uint256[]) public batchSubmissions;

    // ============ EVENTS ============

    event BatchSubmitted(
        uint256 indexed batchId,
        bytes32 stateRoot,
        uint32 numSignatures,
        address proposer,
        uint64 l2BlockNumber
    );

    event SignatureSubmitted(
        uint256 indexed submissionId,
        bytes32 messageHash,
        uint256 publicKeyX,
        uint256 publicKeyY
    );

    event StateUpdated(
        bytes32 newStateRoot,
        uint64 newL2BlockNumber
    );

    // ============ MODIFIERS ============

    modifier onlySequencer() {
        require(msg.sender == sequencer, "Only sequencer can call");
        _;
    }

    // ============ CONSTRUCTOR ============

    constructor(address _sequencer, address _verifier) {
        require(_sequencer != address(0), "Invalid sequencer");
        require(_verifier != address(0), "Invalid verifier");

        sequencer = _sequencer;
        verifier = IBLSVerifier(_verifier);
        currentStateRoot = bytes32(0);
        l2BlockNumber = 0;
    }

    // ============ EXTERNAL FUNCTIONS ============

    /**
     * @notice Sottomette un batch di firme con prova ZK
     * @param _stateRoot Nuovo state root L2 dopo l'applicazione del batch
     * @param _messageHashes Array di hash dei messaggi firmati
     * @param _publicKeysX Array di coordinate X delle chiavi pubbliche
     * @param _publicKeysY Array di coordinate Y delle chiavi pubbliche
     * @param _proof Prova ZK Groth16 che verifica tutte le firme
     */
    function submitBatchWithProof(
        bytes32 _stateRoot,
        bytes32[] calldata _messageHashes,
        uint256[] calldata _publicKeysX,
        uint256[] calldata _publicKeysY,
        bytes calldata _proof
    ) external onlySequencer {
        require(_messageHashes.length > 0, "Empty batch");
        require(
            _messageHashes.length == _publicKeysX.length &&
            _publicKeysX.length == _publicKeysY.length,
            "Length mismatch"
        );

        uint256 batchId = batchCount;

        // Prepara gli input pubblici per la verifica ZK
        uint256[] memory publicInputs = _preparePublicInputs(
            _messageHashes,
            _publicKeysX,
            _publicKeysY
        );

        // Verifica la prova ZK
        bool isValid = verifier.verifyProof(_proof, publicInputs);
        require(isValid, "Invalid ZK proof");

        // Crea e memorizza il batch
        batches[batchId] = Batch({
            stateRoot: _stateRoot,
            numSignatures: uint32(_messageHashes.length),
            timestamp: uint64(block.timestamp),
            proposer: msg.sender,
            verified: true,
            l2BlockNumber: uint64(l2BlockNumber + 1)
        });

        // Memorizza le submission individuali
        for (uint256 i = 0; i < _messageHashes.length; i++) {
            uint256 submissionId = submissionCount++;

            submissions[submissionId] = SignatureSubmission({
                messageHash: _messageHashes[i],
                publicKeyX: _publicKeysX[i],
                publicKeyY: _publicKeysY[i],
                included: true
            });

            batchSubmissions[batchId].push(submissionId);

            emit SignatureSubmitted(
                submissionId,
                _messageHashes[i],
                _publicKeysX[i],
                _publicKeysY[i]
            );
        }

        // Aggiorna stato L2
        currentStateRoot = _stateRoot;
        l2BlockNumber++;
        batchCount++;

        emit BatchSubmitted(
            batchId,
            _stateRoot,
            uint32(_messageHashes.length),
            msg.sender,
            uint64(l2BlockNumber)
        );

        emit StateUpdated(_stateRoot, uint64(l2BlockNumber));
    }

    /**
     * @notice Sottomette una singola firma per inclusion in un batch futuro
     * @dev Le submission sono solo memorizzate, verificate in batch con ZK
     */
    function submitSignature(
        bytes32 _messageHash,
        uint256 _publicKeyX,
        uint256 _publicKeyY
    ) external {
        uint256 submissionId = submissionCount++;

        submissions[submissionId] = SignatureSubmission({
            messageHash: _messageHash,
            publicKeyX: _publicKeyX,
            publicKeyY: _publicKeyY,
            included: false  // Sarà incluso quando un batch viene sottoposto
        });

        emit SignatureSubmitted(
            submissionId,
            _messageHash,
            _publicKeyX,
            _publicKeyY
        );
    }

    // ============ VIEW FUNCTIONS ============

    /**
     * @notice Restituisce i dettagli di un batch
     */
    function getBatch(uint256 _batchId) external view returns (
        bytes32 stateRoot,
        uint32 numSignatures,
        uint64 timestamp,
        address proposer,
        bool verified,
        uint64 l2BlockNumber
    ) {
        Batch memory batch = batches[_batchId];
        return (
            batch.stateRoot,
            batch.numSignatures,
            batch.timestamp,
            batch.proposer,
            batch.verified,
            batch.l2BlockNumber
        );
    }

    /**
     * @notice Restituisce gli ID delle submission in un batch
     */
    function getBatchSubmissions(uint256 _batchId) external view returns (uint256[] memory) {
        return batchSubmissions[_batchId];
    }

    /**
     * @notice Restituisce lo stato corrente di L2
     */
    function getL2State() external view returns (
        bytes32 stateRoot,
        uint256 blockNumber,
        uint256 totalBatches
    ) {
        return (
            currentStateRoot,
            l2BlockNumber,
            batchCount
        );
    }

    /**
     * @notice Verifica se una submission è inclusa in un batch verificato
     */
    function isSignatureVerified(uint256 _submissionId) external view returns (bool) {
        SignatureSubmission memory submission = submissions[_submissionId];
        return submission.included;
    }

    // ============ INTERNAL FUNCTIONS ============

    /**
     * @notice Prepara gli input pubblici per la verifica ZK
     * @dev Gli input devono corrispondere all'ordine nel circuito
     */
    function _preparePublicInputs(
        bytes32[] calldata _messageHashes,
        uint256[] calldata _publicKeysX,
        uint256[] calldata _publicKeysY
    ) internal pure returns (uint256[] memory) {
        // Per un batch di N firme, abbiamo 3N input pubblici:
        // [msgHash1, pkX1, pkY1, msgHash2, pkX2, pkY2, ...]
        uint256[] memory publicInputs = new uint256[](_messageHashes.length * 3);

        for (uint256 i = 0; i < _messageHashes.length; i++) {
            publicInputs[i * 3] = uint256(_messageHashes[i]);
            publicInputs[i * 3 + 1] = _publicKeysX[i];
            publicInputs[i * 3 + 2] = _publicKeysY[i];
        }

        return publicInputs;
    }

    /**
     * @notice Aggiorna il verifier (solo per emergenze/upgrade)
     */
    function updateVerifier(address _newVerifier) external onlySequencer {
        require(_newVerifier != address(0), "Invalid verifier");
        verifier = IBLSVerifier(_newVerifier);
    }
}