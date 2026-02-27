/**
 * EIP-191 Personal Sign Message Module
 * Standard Ethereum message signing with prefix
 * Used for authentication, proof of ownership, and simple signing
 */

const ethers = require('ethers');
const crypto = require('crypto');

class EIP191Module {
    constructor(config) {
        this.provider = config.provider || new ethers.providers.JsonRpcProvider(config.rpcUrl);
        this.signer = config.signer || (config.privateKey 
            ? new ethers.Wallet(config.privateKey, this.provider)
            : this.provider.getSigner());
    }
    
    /**
     * Sign personal message (EIP-191)
     * Adds "\x19Ethereum Signed Message:\n" + len(message) prefix
     */
    async signMessage(message) {
        try {
            const signature = await this.signer.signMessage(message);
            const sig = ethers.utils.splitSignature(signature);
            const messageHash = ethers.utils.hashMessage(message);
            
            return {
                success: true,
                message: message,
                signature: signature,
                messageHash: messageHash,
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
     * Sign bytes
     */
    async signBytes(bytes) {
        try {
            const bytesArray = ethers.utils.arrayify(bytes);
            const signature = await this.signer.signMessage(bytesArray);
            const sig = ethers.utils.splitSignature(signature);
            
            return {
                success: true,
                bytes: bytes,
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
     * Verify message signature
     */
    verifyMessage(message, signature) {
        try {
            const recoveredAddress = ethers.utils.verifyMessage(message, signature);
            
            return {
                success: true,
                message: message,
                signature: signature,
                signer: recoveredAddress,
                messageHash: ethers.utils.hashMessage(message)
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Check if signature is valid for address
     */
    isValidSignature(message, signature, expectedAddress) {
        try {
            const recoveredAddress = ethers.utils.verifyMessage(message, signature);
            const isValid = recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
            
            return {
                success: true,
                isValid: isValid,
                recovered: recoveredAddress,
                expected: expectedAddress
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
     * Sign authentication challenge (SIWE-style)
     */
    async signAuth(domain, nonce, issuedAt = null) {
        try {
            const address = await this.signer.getAddress();
            const timestamp = issuedAt || new Date().toISOString();
            
            const message = `${domain} wants you to sign in with your Ethereum account:\n${address}\n\nURI: https://${domain}\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${timestamp}`;
            
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign simple authentication (login)
     */
    async signLogin(nonce, timestamp = null) {
        try {
            const ts = timestamp || Date.now();
            const message = `Login to My Money Factory\n\nNonce: ${nonce}\nTimestamp: ${ts}`;
            
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign proof of ownership
     */
    async signOwnership(address, timestamp = null) {
        try {
            const ts = timestamp || Date.now();
            const message = `I am the owner of ${address}\n\nTimestamp: ${ts}`;
            
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create signed note for mixer
     */
    async createNote(commitment, nullifier, secret) {
        try {
            const note = {
                commitment: commitment,
                nullifier: nullifier,
                secret: secret,
                timestamp: Date.now(),
                signer: await this.signer.getAddress()
            };
            
            const noteJson = JSON.stringify(note);
            const sigResult = await this.signMessage(noteJson);
            
            if (!sigResult.success) {
                return sigResult;
            }
            
            const signedNote = {
                ...note,
                signature: sigResult.signature
            };
            
            // Encode as base64
            const encoded = Buffer.from(JSON.stringify(signedNote)).toString('base64');
            
            return {
                success: true,
                note: signedNote,
                encoded: encoded
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Verify and decode signed note
     */
    verifyNote(encoded) {
        try {
            const decoded = Buffer.from(encoded, 'base64').toString('utf8');
            const note = JSON.parse(decoded);
            
            const { signature, ...noteData } = note;
            const message = JSON.stringify(noteData);
            
            const verification = this.verifyMessage(message, signature);
            
            if (!verification.success) {
                return verification;
            }
            
            return {
                success: true,
                note: note,
                isValid: verification.signer.toLowerCase() === note.signer.toLowerCase(),
                signer: verification.signer
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
     * Sign commitment hash
     */
    async signCommitment(commitment) {
        try {
            const message = `Mixer Commitment\n\nCommitment: ${commitment}`;
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign nullifier hash
     */
    async signNullifier(nullifier) {
        try {
            const message = `Withdrawal Nullifier\n\nNullifier: ${nullifier}`;
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign terms acceptance
     */
    async signTerms(version, timestamp = null) {
        try {
            const ts = timestamp || Date.now();
            const message = `I accept the Terms of Service (v${version})\n\nTimestamp: ${ts}`;
            
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign transaction intent for relayer
     */
    async signIntent(to, data, value, deadline) {
        try {
            const intent = {
                to: to,
                data: data,
                value: value.toString(),
                deadline: deadline,
                from: await this.signer.getAddress()
            };
            
            const message = JSON.stringify(intent);
            const sigResult = await this.signMessage(message);
            
            if (!sigResult.success) {
                return sigResult;
            }
            
            return {
                success: true,
                intent: intent,
                signature: sigResult.signature,
                messageHash: sigResult.messageHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign challenge for 2FA
     */
    async sign2FA(code, timestamp = null) {
        try {
            const ts = timestamp || Date.now();
            const message = `2FA Code: ${code}\nTimestamp: ${ts}`;
            
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create recovery signature
     */
    async signRecovery(newAddress, timestamp = null) {
        try {
            const ts = timestamp || Date.now();
            const currentAddress = await this.signer.getAddress();
            const message = `Account Recovery\n\nOld Address: ${currentAddress}\nNew Address: ${newAddress}\nTimestamp: ${ts}`;
            
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Recover address from message hash and signature
     */
    recoverAddress(messageHash, signature) {
        try {
            const address = ethers.utils.recoverAddress(messageHash, signature);
            
            return {
                success: true,
                address: address,
                messageHash: messageHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get compact signature (65 bytes)
     */
    getCompactSignature(signature) {
        try {
            const sig = ethers.utils.splitSignature(signature);
            
            return {
                success: true,
                signature: signature,
                compact: sig.compact,
                r: sig.r,
                s: sig.s,
                v: sig.v,
                length: ethers.utils.arrayify(sig.compact).length
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create deterministic nonce for replay protection
     */
    createNonce(data) {
        return crypto.randomBytes(32).toString('hex');
    }
    
    /**
     * Sign with prefix (custom prefix)
     */
    async signWithPrefix(message, prefix) {
        try {
            const prefixedMessage = `${prefix}${message}`;
            return await this.signMessage(prefixedMessage);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = EIP191Module;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY',
        privateKey: 'YOUR_PRIVATE_KEY'
    };
    
    const eip191 = new EIP191Module(config);
    
    // Example: Sign login
    eip191.signLogin('nonce_123', Date.now()).then(result => {
        console.log('Login signature:', result);
        
        // Verify
        const verification = eip191.verifyMessage(result.message, result.signature);
        console.log('Verified signer:', verification.signer);
    });
}
