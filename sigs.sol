pragma solidity ^0.4.0;

contract Mapping {

  CustomMap internal sigsMap;

  struct CustomMap {
     mapping (bytes32 => uint) maps;
     bytes32[] keys;
  }

  function put(bytes32 txHash, uint value) internal {
    //  address sender = msg.sender;
    //  uint256 value = msg.value;
     bool contain = contains(txHash);
     if (contain) {
       sigsMap.maps[txHash] = sigsMap.maps[txHash] + value;
     } else {
       sigsMap.maps[txHash] = value;
       sigsMap.keys.push(txHash);
     }
  }

  function iterator() constant returns (bytes32[], uint[]){
      uint len = sigsMap.keys.length;
      bytes32[] memory keys = new bytes32[](len);
      uint[] memory values = new uint[](len);
      for (uint i = 0 ; i <  len ; i++) {
         bytes32 key = sigsMap.keys[i];
         keys[i] = key;
         values[i] = sigsMap.maps[key];
      }
      return (keys, values);
  }

  function remove(bytes32 _txHash) internal returns (bool) {
      int index = indexOf(_txHash);
      if (index < 0) {
          return false;
      }
      delete sigsMap.maps[_txHash];
      delete sigsMap.keys[uint(index)];
      return true;
  }

  function indexOf(bytes32 _txHash) constant returns (int) {
    uint len = sigsMap.keys.length;
    if (len == 0) {
        return -1;
    }
    for (uint i = 0 ; i < len ;i++) {
      if (sigsMap.keys[i] == _txHash) {
          return int(i);
      }
    }
    return -1;
  }

  function contains(bytes32 _txHash) constant returns (bool) {
      if (sigsMap.keys.length == 0) {
         return false;
      }
      uint len = sigsMap.keys.length;
      for (uint i = 0 ; i < len ; i++) {
          if (sigsMap.keys[i] == _txHash) {
            return true;
          }
      }
      return false;
  }
  
  function twoThirdSigs(uint N) constant returns (bytes32) {
      bytes32[] memory hashes;
      uint[] memory count;
      (hashes, count) = iterator();
      for(uint i = 0; i < count.length; i++) {
          if (count[i] > (N - (N - 1)/3)) {
              return hashes[i];
          }
      }
      return bytes32(0);
  }
}

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

contract Arbitration is Decode, Mapping {
    struct Paras {
        // uint p;
        uint v;
    }
    // struct Speaker {
    //     address speakerAddr;
    //     bytes32 txHash;
    //     bytes32 prefixedHash;
    //     bytes sig;
    // }
    struct Delegators {
        bytes sig; 
        // bytes32 txHash;
        bytes32 prefixedHash;
        address addr;
        uint i;
    }
    struct Round {
        Paras   paras;
        // Speaker speaker;
        uint    consents;
        Delegators [] signers;
        // mapping(uint => mapping(address => Delegators)) signers;
    }
    
    uint constant _sizeOfnotaries = 3;
    // Hardcoding the members of notaries in smart contract. Here only provides sample addrs for logic-revision.
    address[_sizeOfnotaries] addrList = [ 
        0x63987fbd0d132c3dbbec93a883520be3f377d66a,
        0x98b1c61857d0606320c7c5acd1a296586aade6b8,
        0xeb6aa4e6f12f84281c5a3cac2fe3c4c190d44298
    ];
    Round internal round;
    mapping(bytes32 => uint) count;
    
    event ProposeEvent(bool returnValue);
    
    // Getter for the index of addrList.
    function getIndex(address addr) constant returns (uint) {
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
    function propose(bytes32 txHash, bytes sig, uint i) returns (bool) {
        // Prevent from too many sigs. ***
        // if (round.consents > (_sizeOfnotaries - (_sizeOfnotaries - 1)/3)) {
        //     throw;
        // }
        bytes32 prefixedHash = addPrefix(txHash);
        // round.speaker = Speaker({
        //     speakerAddr: msg.sender, 
        //     txHash: txHash, 
        //     prefixedHash: prefixedHash,
        //     sig: sig
        // });
        round.signers.push(Delegators(sig, prefixedHash, msg.sender, i));
        // round.consents += 1;
        return true;
    }
    
    // // Validate if the info proposed by current speaker is valid. 
    // function getAndValidate(bytes32 txHash, uint p, uint v) constant returns (bool, bytes32) {
    //     // txHash SHOULD equal to others.
    //     if (txHash != round.speaker.txHash) {
    //         throw;
    //     }
    //     // View number SHOULD be the same.
    //     if (p != round.paras.p || v != round.paras.v) {
    //         throw;
    //     }
    //     // Check if the sig is valid.
    //     address decodeAddr = decode(round.speaker.sig, round.speaker.prefixedHash);
    //     if (decodeAddr != round.speaker.speakerAddr) {
    //         throw;
    //     }
    //     // Check if the address proposing info is valid.
    //     if (addrList[getIndex(decodeAddr)] == addrList[p]) {
    //         throw;
    //     }
    //     return (true, round.speaker.txHash);
    // }
    
    // // Add its own sig if getAndValidate() returns true.
    // function addSign(bytes sig, uint i) returns (bool) {
    //     // Prevent from too many sigs.
    //     if (round.consents > (_sizeOfnotaries - (_sizeOfnotaries - 1)/3)) {
    //         throw;
    //     }
    //     bytes32 prefixedHash = addPrefix(round.speaker.txHash);
    //     round.signers.push(Delegators(sig, prefixedHash, msg.sender, i));
    //     round.consents += 1;
    //     return true;
    // }
    
    // Current speaker collects the 2/3 sigs and verify if they are valid.
    function getConsentsAndSigs() constant returns (bool, bytes32) {
        bytes32 hashFinal;
        // Verfiy and count only if the length of signs have reached 2/3 of all addrs.
        if (round.signers.length >= _sizeOfnotaries - (_sizeOfnotaries - 1)/3) {
            // Iterate round.signers
            for(uint i = 0; i < round.signers.length; i++) {
                // i and the position of addr in addrList should match.
                if (getIndex(round.signers[i].addr) != round.signers[i].i) {
                    throw;
                }
                // Check if the sigs are valid. 
                if (decode(round.signers[i].sig, round.signers[i].prefixedHash) != round.signers[i].addr) {
                    throw;
                }
                // Check if prefixedHash match.
                // sigArray[0] = round.signers[i].prefixedHash;
                put(round.signers[i].prefixedHash, 1);
                hashFinal = twoThirdSigs(_sizeOfnotaries);
                if (hashFinal != bytes32(0)) {
                    return (true, hashFinal);
                }
            }
        }
        return (false, bytes32(0));

    }
    
    // Call cross-chain smart contract if getConsentsAndSigs() returns true.
    function checkSigs() {
        bool ok;
        bytes32 hash;
        (ok, hash) = getConsentsAndSigs();
        if (ok == true) {
            // TODO call cross-chain sc.
        }
    }
    
    function timeoutAndChangeV() { // Invoked if changeV passed.
        round.paras.v += 1;
    }

// default call
    function (){
        throw;
    }
}

