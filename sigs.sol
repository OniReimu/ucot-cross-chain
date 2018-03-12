pragma solidity ^0.4.0;

contract Decode {
    // Entry to verify a signature.
    function decode(bytes memory sig, bytes32 prefixedHash) internal returns (address) {
        bytes memory signedString = sig;
        
        bytes32 r = bytesToBytes32(slice(signedString, 0, 32));
        bytes32 s = bytesToBytes32(slice(signedString, 32, 32));
        byte v = slice(signedString, 64, 1)[0];
        return ecrecoverDecode(prefixedHash, r, s, v);
    }
    
    // Slice the metadata to different specific portions.
    function slice(bytes memory data, uint start, uint len) private returns (bytes) {
        bytes memory b = new bytes(len);
        
        for(uint i = 0; i < len; i++) {
            b[i] = data[i + start];   
        }
        return b;
    }
    
    // Recover PublicKey by using ecrecover().
    function ecrecoverDecode(bytes32 prefixedHash, bytes32 r, bytes32 s, byte v1) private returns (address addr) {
        uint8 v = uint8(v1) + 27;
        addr = ecrecover(prefixedHash, v, r, s);
    }
    
    // Convert bytes to bytes32.
    function bytesToBytes32(bytes memory source) private returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }
}

contract Arbitration is Decode {
    struct Paras {
        uint p;
        uint v;
    }
    struct Speaker {
        address speakerAddr;
        bytes32 txHash;
        bytes32 prefixedHash;
        bytes sig;
    }
    struct Delegators {
        bytes sig; 
        bytes32 prefixedHash;
        address addr;
        uint i;
    }
    struct Round {
        Paras   paras;
        Speaker speaker;
        uint    consents;
        // mapping(address => Delegators) signers;
        Delegators [] signers;
        // mapping(uint => mapping(address => Delegators)) signers;
    }
    
    uint constant _sizeOfnotaries = 3;
    // Hardcoding the members of notaries in smart contract. Here only provides sample addrs for logic-revision.
    address[_sizeOfnotaries] addrList = [ 
        0x4f36bb3506249fced0260add3b8a6fa3cf5a38c2,
        0x7e64abb068b3f0d733b2b09ac6513901ba911a36,
        0x1d2015c93784bad766e4bf1885e67c9235469207
    ];
    Round internal round;
    
    // Getter for the index of addrList.
    function getIndex(address addr) returns (uint) {
        for(uint i = 0; i < _sizeOfnotaries; i++) {
            if (addr == addrList[i]) {
                return i;
            }   
        }
    }
    
    // Add prefix "\x19Ethereum Signed Message:\n32" for recovering work. 
    // Look at https://ethereum.stackexchange.com/questions/15364/ecrecover-from-geth-and-web3-eth-sign
    function addPrefix(bytes32 txHash) constant returns (bytes32) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHash = keccak256(prefix, txHash);
        return prefixedHash;
    }
    
    // Current speaker proposes the sig info.
    function propose(bytes32 txHash, bytes sig, uint p, uint v) {
        bytes32 prefixedHash = addPrefix(txHash);
        round.speaker = Speaker({
            speakerAddr: msg.sender, 
            txHash: txHash, 
            prefixedHash: prefixedHash,
            sig: sig
        });
        round.paras = Paras(p, v);
        round.consents = 0;
    }
    
    // Validate if the info proposed by current speaker is valid. 
    function getAndValidate(bytes32 txHash, uint p, uint v) constant returns (bool, bytes32) {
        // txHash SHOULD equal to others.
        if (txHash != round.speaker.txHash) {
            throw;
        }
        // View number SHOULD be the same.
        if (p != round.paras.p || v != round.paras.v) {
            throw;
        }
        // Check if the sig is valid.
        address decodeAddr = decode(round.speaker.sig, round.speaker.prefixedHash);
        if (decodeAddr != round.speaker.speakerAddr) {
            throw;
        }
        // Check if the address proposing info is valid.
        if (addrList[getIndex(decodeAddr)] == addrList[p]) {
            throw;
        }
        return (true, round.speaker.txHash);
    }
    
    // Add its own sig if getAndValidate() returns true.
    function addSign(bytes sig, uint i) returns (bool) {
        // Prevent from too many sigs.
        if (round.consents > (_sizeOfnotaries - (_sizeOfnotaries - 1)/3)) {
            throw;
        }
        bytes32 prefixedHash = addPrefix(round.speaker.txHash);
        round.signers.push(Delegators(sig, prefixedHash, msg.sender, i));
        round.consents += 1;
        return true;
    }
    
    // Current speaker collects the 2/3 sigs and verify if they are valid.
    function getConsentsAndSigs() constant returns (bool) {
        // Only current speaker is eligiable to do this.
        if (msg.sender != round.speaker.speakerAddr) {
            throw;
        }
        // Check if the number of sigs has reached 2/3 of the length of addList.
        if (round.consents < (_sizeOfnotaries - (_sizeOfnotaries - 1)/3)) {
            return false;
        } else {
            if (round.signers.length != round.consents) {
                throw;
            }
            // Iterate round.signers
            for(uint i = 0; i < round.consents; i++) {
                // i and the position of addr in addrList should match.
                if (getIndex(round.signers[i].addr) != round.signers[i].i) {
                    throw;
                }
                // Check if the sigs are valid. 
                if (decode(round.signers[i].sig, round.signers[i].prefixedHash) != round.signers[i].addr) {
                    throw;
                }
            }
            return true;
        }
    }
    
    // Call cross-chain smart contract if getConsentsAndSigs() returns true.
    function checkSigs() {
        if (getConsentsAndSigs() == true) {
            // TODO call cross-chain sc.
        }
    }
    
    // TODO
    function timeoutAndChangeV() {
        
    }

// default call
    function (){
        throw;
    }
}

