/**
 * EIP-191 Personal Message Signing Module
 * Standard message signing with "Ethereum Signed Message" prefix
 * Used for authentication, proof of ownership, and off-chain verification
 */

const ethers = require('ethers');

class EIP191Module {
    constructor(config) {
        this.provider = config.provider || new ethers.providers.JsonRpcProvider(config.rpcUrl);
        this.signer = config.signer || (config.privateKey 
            ? new ethers.Wallet(config.privateKey, this.provider)
            : this.provider.getSigner());
    }
    
    /**
     * Sign a personal message (EIP-191)
     * Automatically adds "Ethereum Signed Message" prefix
     */
    async signMessage(message) {
        try {
            const signature = await this.signer.signMessage(message);
            const sig = ethers.utils.splitSignature(signature);
            
            const messageHash = ethers.utils.hashMessage(message);
            const signer = await this.signer.getAddress();
            
            return {
                success: true,
                message: message,
                signature: signature,
                messageHash: messageHash,
                r: sig.r,
                s: sig.s,
                v: sig.v,
                signer: signer
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign message with bytes
     */
    async signBytes(bytes) {
        try {
            const signature = await this.signer.signMessage(ethers.utils.arrayify(bytes));
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
                recoveredAddress: recoveredAddress
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
                recoveredAddress: recoveredAddress,
                expectedAddress: expectedAddress
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign authentication challenge
     */
    async signAuthChallenge(nonce, timestamp) {
        try {
            const message = `Sign this message to authenticate with My Money Factory\n\nNonce: ${nonce}\nTimestamp: ${timestamp}`;
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
    async signProofOfOwnership(address, timestamp) {
        try {
            const message = `I am the owner of ${address}\n\nTimestamp: ${timestamp}`;
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign login message (for web3 auth)
     */
    async signLogin(domain, timestamp, nonce) {
        try {
            const message = `${domain} wants you to sign in with your Ethereum account:\n\n` +
                           `${await this.signer.getAddress()}\n\n` +
                           `Sign in to My Money Factory\n\n` +
                           `URI: https://${domain}\n` +
                           `Nonce: ${nonce}\n` +
                           `Issued At: ${new Date(timestamp).toISOString()}`;
            
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign commitment (for mixer deposit)
     */
    async signCommitment(commitment) {
        try {
            const message = `Mixer Commitment: ${commitment}`;
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign nullifier (for mixer withdrawal)
     */
    async signNullifier(nullifierHash) {
        try {
            const message = `Nullifier Hash: ${nullifierHash}`;
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign terms of service agreement
     */
    async signTermsOfService(version, timestamp) {
        try {
            const message = `I agree to the Terms of Service (Version ${version})\n\nTimestamp: ${timestamp}`;
            return await this.signMessage(message);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create signed withdrawal note
     */
    async createSignedNote(commitment, nullifierHash, secret) {
        try {
            const noteData = {
                commitment: commitment,
                nullifierHash: nullifierHash,
                secret: secret,
                timestamp: Date.now(),
                signer: await this.signer.getAddress()
            };
            
            const message = JSON.stringify(noteData);
            const sigResult = await this.signMessage(message);
            
            if (!sigResult.success) {
                return sigResult;
            }
            
            return {
                success: true,
                note: {
                    ...noteData,
                    signature: sigResult.signature
                },
                encoded: Buffer.from(JSON.stringify({
                    ...noteData,
                    signature: sigResult.signature
                })).toString('base64')
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Verify signed note
     */
    verifySignedNote(encodedNote) {
        try {
            const noteJson = Buffer.from(encodedNote, 'base64').toString('utf-8');
            const note = JSON.parse(noteJson);
            
            const { signature, ...noteData } = note;
            const message = JSON.stringify(noteData);
            
            const verification = this.verifyMessage(message, signature);
            
            return {
                success: true,
                note: note,
                isValid: verification.success,
                recoveredAddress: verification.recoveredAddress
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign transaction intent (for relayer)
     */
    async signTransactionIntent(to, data, value, deadline) {
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
                signature: sigResult.signature
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Sign data hash (compact signature)
     */
    async signHash(hash) {
        try {
            const hashBytes = ethers.utils.arrayify(hash);
            const signature = await this.signer.signMessage(hashBytes);
            const sig = ethers.utils.splitSignature(signature);
            
            return {
                success: true,
                hash: hash,
                signature: signature,
                r: sig.r,
                s: sig.s,
                v: sig.v,
                compact: sig.compact
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Recover address from signature
     */
    recoverAddress(message, signature) {
        try {
            const recoveredAddress = ethers.utils.verifyMessage(message, signature);
            
            return {
                success: true,
                message: message,
                signature: signature,
                recoveredAddress: recoveredAddress
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Create compact signature (65 bytes)
     */
    getCompactSignature(signature) {
        try {
            const sig = ethers.utils.splitSignature(signature);
            
            return {
                success: true,
                signature: signature,
                compact: sig.compact,
                length: ethers.utils.arrayify(sig.compact).length
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = EIP191Module;

// Example Solidity contract for EIP-191 verification
const EIP191_VERIFIER_EXAMPLE = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EIP191Verifier {
    /**
     * Verify EIP-191 signature
     * Returns true if signature is valid for message and signer
     */
    function verifySignature(
        string memory message,
        bytes memory signature,
        address expectedSigner
    ) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(message);
        address recoveredSigner = recoverSigner(messageHash, signature);
        return recoveredSigner == expectedSigner;
    }
    
    /**
     * Get EIP-191 message hash
     */
    function getMessageHash(string memory message) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\\x19Ethereum Signed Message:\\n",
                uintToString(bytes(message).length),
                message
            )
        );
    }
    
    /**
     * Recover signer from signature
     */
    function recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) public pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "Invalid signature v value");
        
        return ecrecover(messageHash, v, r, s);
    }
    
    function uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
`;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY',
        privateKey: 'YOUR_PRIVATE_KEY'
    };
    
    const eip191 = new EIP191Module(config);
    
    // Example: Sign authentication message
    eip191.signAuthChallenge(
        'abc123',
        Date.now()
    ).then(result => {
        console.log('Auth signature:', result);
        
        // Verify the signature
        const verification = eip191.verifyMessage(result.message, result.signature);
        console.log('Verified:', verification);
    });
}
