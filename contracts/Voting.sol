// SPDX-License-Identifier: BSD-3-Clause-Clear

pragma solidity >=0.8.19 <0.9.0;

import "@luxfi/contracts/fhe/FHE.sol";
import {Euint8} from "@luxfi/contracts/fhe/IFHE.sol";
import "@luxfi/contracts/fhe/access/Permissioned.sol";

contract Voting is Permissioned {
    uint8 internal constant MAX_OPTIONS = 4;

    // Pre-compute these to prevent unnecessary gas usage for the users
    euint32 internal _u32Sixteen = FHE.asEuint32(16);
    euint8[MAX_OPTIONS] internal _encOptions = [FHE.asEuint8(0), FHE.asEuint8(1), FHE.asEuint8(2), FHE.asEuint8(3)];

    string public proposal;
    string[] public options;
    uint public voteEndTime;
    euint16[MAX_OPTIONS] internal _tally; // Since every vote is worth 1, I assume we can use a 16-bit integer

    euint8 internal _winningOption;
    euint16 internal _winningTally;

    // Decrypted results
    uint8 public winningOptionDecrypted;
    uint16 public winningTallyDecrypted;
    bool public resultsDecrypted;

    mapping(address => euint8) internal _votes;

    event VoteCast(address indexed voter);
    event VoteFinalized();
    event ResultsDecrypted(uint8 winningOption, uint16 winningTally);

    error InvalidVoteOption();
    error VotingNotOver();
    error VotingOver();
    error AlreadyVoted();
    error NoVoteFound();
    error ResultsNotReady();
    error TooManyOptions();

    constructor(string memory _proposal, string[] memory _options, uint votingPeriod) {
        if (_options.length > MAX_OPTIONS) revert TooManyOptions();

        proposal = _proposal;
        options = _options;
        voteEndTime = block.timestamp + votingPeriod;
    }

    function vote(Euint8 memory voteBytes) public {
        if (block.timestamp >= voteEndTime) revert VotingOver();
        if (FHE.isInitialized(_votes[msg.sender])) revert AlreadyVoted();

        euint8 encryptedVote = FHE.asEuint8(voteBytes); // Cast bytes into an encrypted type

        // Validate the vote is within valid range [0, options.length - 1]
        // We use FHE.select to conditionally accept the vote
        // Invalid votes are silently treated as abstentions (no tally change)
        ebool isGteMin = encryptedVote.gte(_encOptions[0]);
        ebool isLteMax = encryptedVote.lte(_encOptions[options.length - 1]);
        ebool isValid = FHE.and(isGteMin, isLteMax);

        // Store the vote (even if invalid, the voter used their vote)
        _votes[msg.sender] = encryptedVote;

        // Only add to tally if valid (encrypted conditional)
        _addToTally(encryptedVote, isValid);

        emit VoteCast(msg.sender);
    }

    function finalize() public {
        if (block.timestamp <= voteEndTime) revert VotingNotOver();

        _winningOption = _encOptions[0];
        _winningTally = _tally[0];
        for (uint8 i = 1; i < options.length; i++) {
            euint16 newWinningTally = FHE.max(_winningTally, _tally[i]);
            _winningOption = FHE.select(newWinningTally.gt(_winningTally), _encOptions[i], _winningOption);
            _winningTally = newWinningTally;
        }

        // Decrypt results synchronously
        FHE.decrypt(_winningOption);
        FHE.decrypt(_winningTally);
        winningOptionDecrypted = FHE.reveal(_winningOption);
        winningTallyDecrypted = FHE.reveal(_winningTally);
        resultsDecrypted = true;

        emit VoteFinalized();
        emit ResultsDecrypted(winningOptionDecrypted, winningTallyDecrypted);
    }

    /// @notice Get the winning option and tally (only after decryption)
    function winning() public view returns (uint8, uint16) {
        if (block.timestamp <= voteEndTime) revert VotingNotOver();
        if (!resultsDecrypted) revert ResultsNotReady();
        return (winningOptionDecrypted, winningTallyDecrypted);
    }

    function getUserVote(
        Permission memory signature
    ) public view onlySender(signature) returns (bytes memory) {
        if (!FHE.isInitialized(_votes[msg.sender])) revert NoVoteFound();
        return FHE.sealoutput(_votes[msg.sender], signature.publicKey);
    }

    function _addToTally(euint8 option, ebool isValid) internal {
        // We don't want to leak the user's vote, so we have to change the tally of every option.
        // So for example, if the user voted for option 1:
        // tally[0] = tally[0] + enc(0)
        // tally[1] = tally[1] + enc(1)
        // etc ..
        for (uint8 i = 0; i < options.length; i++) {
            // Only add if vote is valid AND matches this option
            ebool matchesOption = option.eq(_encOptions[i]);
            ebool shouldAdd = FHE.and(isValid, matchesOption);
            _tally[i] = FHE.add(_tally[i], shouldAdd.toU16()); // `and()` result is enc(0) or enc(1)
        }
    }
}
