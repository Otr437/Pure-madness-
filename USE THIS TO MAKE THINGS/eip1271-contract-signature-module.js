/**
 * EIP-1271 Smart Contract Signature Verification Module
 * Allows smart contracts (like multisigs) to validate signatures
 * Used for contract wallets, DAOs, and account abstraction
 */

const ethers = require('ethers');

class EIP1271Module {
    constructor(config) {
        this.provider = new ethers.providers.JsonRpcProvider(config.rpcUrl);
        
        // EIP-1271 magic value
        this.MAGIC_VALUE = '0x1626ba7e';
        this.MAGIC_VALUE_BYTES32 = '0x20c13b0b';
        
        // EIP-1271 ABI
        this.eip1271ABI = [
            'function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4)',
            'function isValidSignature(bytes memory data, bytes memory signature) external view returns (bytes4)'
        ];
    }
    
    /**
     * Verify signature using EIP-1271
     * Works for both EOA and smart contract wallets
     */
    async verifySignature(contractAddress, hash, signature) {
        try {
            const contract = new ethers.Contract(
                contractAddress,
                this.eip1271ABI,
                this.provider
            );
            
            let magicValue;
            try {
                // Try bytes32 version first
                magicValue = await contract['isValidSignature(bytes32,bytes)'](hash, signature);
            } catch {
                // Fallback to bytes version
                magicValue = await contract['isValidSignature(bytes,bytes)'](hash, signature);
            }
            
            const isValid = magicValue === this.MAGIC_VALUE || magicValue === this.MAGIC_VALUE_BYTES32;
            
            return {
                success: true,
                isValid: isValid,
                magicValue: magicValue,
                contractAddress: contractAddress
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Check if address is a contract (not EOA)
     */
    async isContract(address) {
        try {
            const code = await this.provider.getCode(address);
            const isContract = code !== '0x';
            
            return {
                success: true,
                address: address,
                isContract: isContract,
                code: code
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Verify signature (works for both EOA and smart contracts)
     */
    async verifyUniversalSignature(message, signature, signer) {
        try {
            // Check if signer is a contract
            const contractCheck = await this.isContract(signer);
            
            if (!contractCheck.success) {
                return contractCheck;
            }
            
            if (contractCheck.isContract) {
                // Use EIP-1271 for contracts
                const messageHash = ethers.utils.hashMessage(message);
                return await this.verifySignature(signer, messageHash, signature);
            } else {
                // Use standard verification for EOAs
                const recoveredAddress = ethers.utils.verifyMessage(message, signature);
                const isValid = recoveredAddress.toLowerCase() === signer.toLowerCase();
                
                return {
                    success: true,
                    isValid: isValid,
                    recoveredAddress: recoveredAddress,
                    signerType: 'EOA'
                };
            }
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Verify typed data signature (EIP-712 + EIP-1271)
     */
    async verifyTypedDataSignature(domain, types, value, signature, signer) {
        try {
            const contractCheck = await this.isContract(signer);
            
            if (!contractCheck.success) {
                return contractCheck;
            }
            
            const hash = ethers.utils._TypedDataEncoder.hash(domain, types, value);
            
            if (contractCheck.isContract) {
                // Use EIP-1271 for contract wallets
                return await this.verifySignature(signer, hash, signature);
            } else {
                // Use standard verification for EOAs
                const recoveredAddress = ethers.utils.recoverAddress(hash, signature);
                const isValid = recoveredAddress.toLowerCase() === signer.toLowerCase();
                
                return {
                    success: true,
                    isValid: isValid,
                    recoveredAddress: recoveredAddress,
                    signerType: 'EOA'
                };
            }
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create signature that works with EIP-1271 contract wallets
     */
    async createContractWalletSignature(contractAddress, message, ownerSigner) {
        try {
            // Sign the message with the owner's EOA
            const messageHash = ethers.utils.hashMessage(message);
            const signature = await ownerSigner.signMessage(ethers.utils.arrayify(messageHash));
            
            // Verify it works with the contract wallet
            const verification = await this.verifySignature(contractAddress, messageHash, signature);
            
            return {
                success: true,
                message: message,
                messageHash: messageHash,
                signature: signature,
                contractAddress: contractAddress,
                isValid: verification.isValid
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Verify multisig signature
     */
    async verifyMultisigSignature(multisigAddress, hash, signatures, threshold) {
        try {
            const multisigABI = [
                'function checkSignatures(bytes32 dataHash, bytes memory signatures) external view',
                'function getThreshold() external view returns (uint256)'
            ];
            
            const multisig = new ethers.Contract(multisigAddress, multisigABI, this.provider);
            
            // Check if signatures are valid
            await multisig.checkSignatures(hash, signatures);
            
            const currentThreshold = await multisig.getThreshold();
            
            return {
                success: true,
                isValid: true,
                multisigAddress: multisigAddress,
                threshold: currentThreshold.toNumber(),
                requiredThreshold: threshold
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message,
                isValid: false
            };
        }
    }
    
    /**
     * Check if contract implements EIP-1271
     */
    async supportsEIP1271(contractAddress) {
        try {
            const contract = new ethers.Contract(
                contractAddress,
                this.eip1271ABI,
                this.provider
            );
            
            // Try to call the function to see if it exists
            const testHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('test'));
            const testSig = '0x' + '00'.repeat(65);
            
            try {
                await contract['isValidSignature(bytes32,bytes)'](testHash, testSig);
                return {
                    success: true,
                    supports: true,
                    contractAddress: contractAddress
                };
            } catch (error) {
                // If error is about function not existing, it doesn't support EIP-1271
                if (error.message.includes('function') || error.message.includes('not found')) {
                    return {
                        success: true,
                        supports: false,
                        contractAddress: contractAddress
                    };
                }
                // Otherwise, it might support it but signature is invalid
                return {
                    success: true,
                    supports: true,
                    contractAddress: contractAddress
                };
            }
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Batch verify multiple signatures
     */
    async batchVerifySignatures(verifications) {
        try {
            const promises = verifications.map(v => 
                this.verifyUniversalSignature(v.message, v.signature, v.signer)
            );
            
            const results = await Promise.all(promises);
            
            const allValid = results.every(r => r.success && r.isValid);
            
            return {
                success: true,
                allValid: allValid,
                results: results
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = EIP1271Module;

// Example Solidity implementation of EIP-1271
const EIP1271_IMPLEMENTATION_EXAMPLE = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * EIP-1271 Implementation for Smart Contract Wallets
 */
contract EIP1271Wallet {
    // EIP-1271 magic value
    bytes4 constant internal MAGICVALUE = 0x1626ba7e;
    
    address public owner;
    mapping(address => bool) public signers;
    
    constructor(address _owner) {
        owner = _owner;
        signers[_owner] = true;
    }
    
    /**
     * EIP-1271: Should return whether the signature provided is valid for the provided hash
     * @param _hash      Hash of the data to be signed
     * @param _signature Signature byte array associated with _hash
     */
    function isValidSignature(
        bytes32 _hash,
        bytes memory _signature
    ) public view returns (bytes4) {
        address recovered = recoverSigner(_hash, _signature);
        
        if (signers[recovered]) {
            return MAGICVALUE;
        }
        
        return 0xffffffff;
    }
    
    /**
     * Recover signer from signature
     */
    function recoverSigner(
        bytes32 _hash,
        bytes memory _signature
    ) internal pure returns (address) {
        require(_signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
        
        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "Invalid v value");
        
        return ecrecover(_hash, v, r, s);
    }
    
    /**
     * Add signer
     */
    function addSigner(address signer) external {
        require(msg.sender == owner, "Only owner");
        signers[signer] = true;
    }
    
    /**
     * Remove signer
     */
    function removeSigner(address signer) external {
        require(msg.sender == owner, "Only owner");
        signers[signer] = false;
    }
}

/**
 * Example Multisig with EIP-1271
 */
contract EIP1271Multisig {
    bytes4 constant internal MAGICVALUE = 0x1626ba7e;
    
    address[] public owners;
    uint256 public threshold;
    
    constructor(address[] memory _owners, uint256 _threshold) {
        require(_threshold > 0 && _threshold <= _owners.length, "Invalid threshold");
        owners = _owners;
        threshold = _threshold;
    }
    
    function isValidSignature(
        bytes32 _hash,
        bytes memory _signatures
    ) public view returns (bytes4) {
        require(_signatures.length >= threshold * 65, "Not enough signatures");
        
        address[] memory signers = new address[](threshold);
        
        for (uint256 i = 0; i < threshold; i++) {
            bytes memory sig = new bytes(65);
            for (uint256 j = 0; j < 65; j++) {
                sig[j] = _signatures[i * 65 + j];
            }
            
            signers[i] = recoverSigner(_hash, sig);
            
            // Check if signer is an owner
            bool isOwner = false;
            for (uint256 k = 0; k < owners.length; k++) {
                if (owners[k] == signers[i]) {
                    isOwner = true;
                    break;
                }
            }
            
            if (!isOwner) {
                return 0xffffffff;
            }
        }
        
        return MAGICVALUE;
    }
    
    function recoverSigner(bytes32 _hash, bytes memory _sig) internal pure returns (address) {
        require(_sig.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            v := byte(0, mload(add(_sig, 96)))
        }
        
        if (v < 27) v += 27;
        
        return ecrecover(_hash, v, r, s);
    }
}
`;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY'
    };
    
    const eip1271 = new EIP1271Module(config);
    
    // Example: Check if address is a contract
    eip1271.isContract('0xContractAddress').then(result => {
        console.log('Is contract:', result);
    });
    
    // Example: Verify signature (works for both EOA and contracts)
    eip1271.verifyUniversalSignature(
        'Hello World',
        '0xSignature',
        '0xSignerAddress'
    ).then(result => {
        console.log('Signature valid:', result.isValid);
    });
}
