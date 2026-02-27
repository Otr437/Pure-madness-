/**
 * EIP-712 Typed Structured Data Signing Module
 * Secure, human-readable message signing
 * Used for permits, meta-transactions, and off-chain signatures
 */

const ethers = require('ethers');

class EIP712Module {
    constructor(config) {
        this.provider = config.provider || new ethers.providers.JsonRpcProvider(config.rpcUrl);
        this.signer = config.signer || (config.privateKey 
            ? new ethers.Wallet(config.privateKey, this.provider)
            : this.provider.getSigner());
        
        this.chainId = config.chainId;
        this.verifyingContract = config.verifyingContract;
    }
    
    /**
     * Create EIP-712 domain separator
     */
    createDomain(name, version, contractAddress = null) {
        return {
            name: name,
            version: version,
            chainId: this.chainId,
            verifyingContract: contractAddress || this.verifyingContract
        };
    }
    
    /**
     * Sign EIP-712 typed data
     */
    async signTypedData(domain, types, value) {
        try {
            // Remove EIP712Domain from types as ethers handles it automatically
            const typesWithoutDomain = { ...types };
            delete typesWithoutDomain.EIP712Domain;
            
            const signature = await this.signer._signTypedData(domain, typesWithoutDomain, value);
            
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
     * Verify EIP-712 signature
     */
    async verifyTypedData(domain, types, value, signature) {
        try {
            const typesWithoutDomain = { ...types };
            delete typesWithoutDomain.EIP712Domain;
            
            const recovered = ethers.utils.verifyTypedData(domain, typesWithoutDomain, value, signature);
            
            return {
                success: true,
                signer: recovered,
                isValid: true
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
     * Create permit signature (EIP-2612)
     * Approve tokens without gas
     */
    async signPermit(tokenAddress, owner, spender, value, deadline, nonce) {
        try {
            const domain = this.createDomain('Token', '1', tokenAddress);
            
            const types = {
                Permit: [
                    { name: 'owner', type: 'address' },
                    { name: 'spender', type: 'address' },
                    { name: 'value', type: 'uint256' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value_data = {
                owner: owner,
                spender: spender,
                value: value.toString(),
                nonce: nonce.toString(),
                deadline: deadline.toString()
            };
            
            const result = await this.signTypedData(domain, types, value_data);
            
            if (result.success) {
                return {
                    success: true,
                    permit: {
                        owner: owner,
                        spender: spender,
                        value: value.toString(),
                        deadline: deadline.toString(),
                        v: result.v,
                        r: result.r,
                        s: result.s
                    },
                    signature: result.signature
                };
            }
            
            return result;
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign meta-transaction for gasless execution
     */
    async signMetaTransaction(from, to, value, data, nonce, deadline) {
        try {
            const domain = this.createDomain('MyMoneyFactory', '1');
            
            const types = {
                MetaTransaction: [
                    { name: 'from', type: 'address' },
                    { name: 'to', type: 'address' },
                    { name: 'value', type: 'uint256' },
                    { name: 'data', type: 'bytes' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value_data = {
                from: from,
                to: to,
                value: value.toString(),
                data: data,
                nonce: nonce.toString(),
                deadline: deadline.toString()
            };
            
            return await this.signTypedData(domain, types, value_data);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign mixer deposit authorization
     */
    async signMixerDeposit(mixer, commitment, denomination, deadline) {
        try {
            const domain = this.createDomain('MixerFactory', '1', mixer);
            
            const types = {
                Deposit: [
                    { name: 'mixer', type: 'address' },
                    { name: 'commitment', type: 'bytes32' },
                    { name: 'denomination', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value = {
                mixer: mixer,
                commitment: commitment,
                denomination: denomination.toString(),
                deadline: deadline.toString()
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
     * Sign vault deployment authorization
     */
    async signVaultDeployment(factory, owner, salt, deadline) {
        try {
            const domain = this.createDomain('VaultFactory', '1', factory);
            
            const types = {
                DeployVault: [
                    { name: 'owner', type: 'address' },
                    { name: 'salt', type: 'bytes32' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value = {
                owner: owner,
                salt: salt,
                deadline: deadline.toString()
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
     * Sign withdrawal authorization
     */
    async signWithdrawal(contract, nullifier, recipient, amount, deadline) {
        try {
            const domain = this.createDomain('PrivacyProtocol', '1', contract);
            
            const types = {
                Withdrawal: [
                    { name: 'nullifier', type: 'bytes32' },
                    { name: 'recipient', type: 'address' },
                    { name: 'amount', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value = {
                nullifier: nullifier,
                recipient: recipient,
                amount: amount.toString(),
                deadline: deadline.toString()
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
     * Create batch signature for multiple operations
     */
    async signBatch(operations, nonce, deadline) {
        try {
            const domain = this.createDomain('MyMoneyFactory', '1');
            
            const types = {
                Operation: [
                    { name: 'to', type: 'address' },
                    { name: 'value', type: 'uint256' },
                    { name: 'data', type: 'bytes' }
                ],
                Batch: [
                    { name: 'operations', type: 'Operation[]' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'deadline', type: 'uint256' }
                ]
            };
            
            const value = {
                operations: operations,
                nonce: nonce.toString(),
                deadline: deadline.toString()
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
     * Sign delegation (EIP-7702)
     */
    async signDelegation(delegateTo, nonce) {
        try {
            const domain = this.createDomain('EIP7702', '1');
            
            const types = {
                Authorization: [
                    { name: 'chainId', type: 'uint256' },
                    { name: 'codeAddress', type: 'address' },
                    { name: 'nonce', type: 'uint256' }
                ]
            };
            
            const value = {
                chainId: this.chainId.toString(),
                codeAddress: delegateTo,
                nonce: nonce.toString()
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
     * Get typed data hash (for verification on-chain)
     */
    getTypedDataHash(domain, types, value) {
        try {
            const typesWithoutDomain = { ...types };
            delete typesWithoutDomain.EIP712Domain;
            
            const hash = ethers.utils._TypedDataEncoder.hash(domain, typesWithoutDomain, value);
            
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
     * Recover signer from typed data signature
     */
    recoverSigner(domain, types, value, signature) {
        try {
            const typesWithoutDomain = { ...types };
            delete typesWithoutDomain.EIP712Domain;
            
            const signer = ethers.utils.verifyTypedData(domain, typesWithoutDomain, value, signature);
            
            return {
                success: true,
                signer: signer
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = EIP712Module;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY',
        privateKey: 'YOUR_PRIVATE_KEY',
        chainId: 1,
        verifyingContract: '0x1234567890123456789012345678901234567890'
    };
    
    const eip712 = new EIP712Module(config);
    
    // Example: Sign permit
    eip712.signPermit(
        '0xTokenAddress',
        '0xOwner',
        '0xSpender',
        ethers.utils.parseEther('100'),
        Math.floor(Date.now() / 1000) + 3600,
        0
    ).then(result => {
        console.log('Permit signature:', result);
    });
}
