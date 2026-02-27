/**
 * EIP-712 Typed Data Signing Module
 * Structured data hashing and signing for human-readable signatures
 * Used for gasless transactions, permits, and off-chain authorization
 */

const ethers = require('ethers');

class EIP712Module {
    constructor(config) {
        this.provider = config.provider || new ethers.providers.JsonRpcProvider(config.rpcUrl);
        this.signer = config.signer || (config.privateKey 
            ? new ethers.Wallet(config.privateKey, this.provider)
            : this.provider.getSigner());
        
        this.chainId = config.chainId;
    }
    
    /**
     * Get domain separator for EIP-712
     */
    async getDomainSeparator(contractAddress, name, version = '1') {
        const chainId = this.chainId || (await this.provider.getNetwork()).chainId;
        
        return {
            name: name,
            version: version,
            chainId: chainId,
            verifyingContract: contractAddress
        };
    }
    
    /**
     * Sign typed data (EIP-712)
     */
    async signTypedData(domain, types, value) {
        try {
            const signature = await this.signer._signTypedData(domain, types, value);
            const sig = ethers.utils.splitSignature(signature);
            
            return {
                success: true,
                signature: signature,
                r: sig.r,
                s: sig.s,
                v: sig.v,
                signer: await this.signer.getAddress()
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create EIP-712 signature for mixer deployment
     */
    async signMixerDeployment(mixerFactoryAddress, userAddress, nonce, deadline) {
        try {
            const domain = await this.getDomainSeparator(
                mixerFactoryAddress,
                'MixerFactory',
                '2'
            );
            
            const types = {
                DeployMixer: [
                    { name: 'user', type: 'address' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value = {
                user: userAddress,
                nonce: nonce,
                deadline: deadline
            };
            
            return await this.signTypedData(domain, types, value);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create EIP-712 signature for vault deployment
     */
    async signVaultDeployment(vaultFactoryAddress, owner, salt, nonce, deadline) {
        try {
            const domain = await this.getDomainSeparator(
                vaultFactoryAddress,
                'VaultFactory',
                '2'
            );
            
            const types = {
                DeployVault: [
                    { name: 'owner', type: 'address' },
                    { name: 'salt', type: 'bytes32' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value = {
                owner: owner,
                salt: salt,
                nonce: nonce,
                deadline: deadline
            };
            
            return await this.signTypedData(domain, types, value);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create EIP-712 signature for permit (ERC20 approval without gas)
     */
    async signPermit(tokenAddress, owner, spender, value, nonce, deadline) {
        try {
            const domain = await this.getDomainSeparator(
                tokenAddress,
                'USD Coin', // Token name
                '2'
            );
            
            const types = {
                Permit: [
                    { name: 'owner', type: 'address' },
                    { name: 'spender', type: 'address' },
                    { name: 'value', type: 'uint256' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const permitValue = {
                owner: owner,
                spender: spender,
                value: value.toString(),
                nonce: nonce,
                deadline: deadline
            };
            
            return await this.signTypedData(domain, types, permitValue);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create EIP-712 signature for meta transaction
     */
    async signMetaTransaction(contractAddress, from, to, value, data, nonce, deadline) {
        try {
            const domain = await this.getDomainSeparator(
                contractAddress,
                'MinimalForwarder',
                '1'
            );
            
            const types = {
                ForwardRequest: [
                    { name: 'from', type: 'address' },
                    { name: 'to', type: 'address' },
                    { name: 'value', type: 'uint256' },
                    { name: 'gas', type: 'uint256' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'data', type: 'bytes' }
                ]
            };
            
            const request = {
                from: from,
                to: to,
                value: value,
                gas: 1000000,
                nonce: nonce,
                data: data
            };
            
            return await this.signTypedData(domain, types, request);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create EIP-712 signature for withdrawal authorization
     */
    async signWithdrawalAuth(mixerAddress, recipient, nullifierHash, relayer, fee, deadline) {
        try {
            const domain = await this.getDomainSeparator(
                mixerAddress,
                'PrivacyMixer',
                '1'
            );
            
            const types = {
                WithdrawalAuth: [
                    { name: 'recipient', type: 'address' },
                    { name: 'nullifierHash', type: 'bytes32' },
                    { name: 'relayer', type: 'address' },
                    { name: 'fee', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value = {
                recipient: recipient,
                nullifierHash: nullifierHash,
                relayer: relayer,
                fee: fee.toString(),
                deadline: deadline
            };
            
            return await this.signTypedData(domain, types, value);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Verify EIP-712 signature
     */
    async verifyTypedDataSignature(domain, types, value, signature, expectedSigner) {
        try {
            const digest = ethers.utils._TypedDataEncoder.hash(domain, types, value);
            const recoveredAddress = ethers.utils.recoverAddress(digest, signature);
            
            const isValid = recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
            
            return {
                success: true,
                isValid: isValid,
                recoveredAddress: recoveredAddress,
                expectedSigner: expectedSigner
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create batch signature for multiple operations
     */
    async signBatchOperation(contractAddress, operations, nonce, deadline) {
        try {
            const domain = await this.getDomainSeparator(
                contractAddress,
                'BatchExecutor',
                '1'
            );
            
            const types = {
                BatchOperation: [
                    { name: 'operations', type: 'Operation[]' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ],
                Operation: [
                    { name: 'to', type: 'address' },
                    { name: 'value', type: 'uint256' },
                    { name: 'data', type: 'bytes' }
                ]
            };
            
            const value = {
                operations: operations,
                nonce: nonce,
                deadline: deadline
            };
            
            return await this.signTypedData(domain, types, value);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get typed data hash (for on-chain verification)
     */
    getTypedDataHash(domain, types, value) {
        try {
            const hash = ethers.utils._TypedDataEncoder.hash(domain, types, value);
            
            return {
                success: true,
                hash: hash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create EIP-712 signature for delegation
     */
    async signDelegation(delegationContract, delegator, delegatee, nonce, expiry) {
        try {
            const domain = await this.getDomainSeparator(
                delegationContract,
                'DelegationManager',
                '1'
            );
            
            const types = {
                Delegation: [
                    { name: 'delegator', type: 'address' },
                    { name: 'delegatee', type: 'address' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'expiry', type: 'uint256' }
                ]
            };
            
            const value = {
                delegator: delegator,
                delegatee: delegatee,
                nonce: nonce,
                expiry: expiry
            };
            
            return await this.signTypedData(domain, types, value);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = EIP712Module;

// Example Solidity contract for EIP-712 verification
const EIP712_VERIFIER_EXAMPLE = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EIP712Verifier {
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    
    bytes32 public constant DEPLOY_MIXER_TYPEHASH = keccak256(
        "DeployMixer(address user,uint256 nonce,uint256 deadline)"
    );
    
    string public constant name = "MixerFactory";
    string public constant version = "2";
    
    function getDomainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }
    
    function verifySignature(
        address user,
        uint256 nonce,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view returns (bool) {
        bytes32 structHash = keccak256(
            abi.encode(DEPLOY_MIXER_TYPEHASH, user, nonce, deadline)
        );
        
        bytes32 digest = keccak256(
            abi.encodePacked("\\x19\\x01", getDomainSeparator(), structHash)
        );
        
        address recovered = ecrecover(digest, v, r, s);
        return recovered == user;
    }
}
`;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY',
        privateKey: 'YOUR_PRIVATE_KEY',
        chainId: 1
    };
    
    const eip712 = new EIP712Module(config);
    
    // Example: Sign mixer deployment
    eip712.signMixerDeployment(
        '0xMixerFactory',
        '0xUserAddress',
        0, // nonce
        Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
    ).then(result => {
        console.log('Signature:', result);
    });
}
