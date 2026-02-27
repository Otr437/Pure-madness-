/**
 * Gas Abstraction Module
 * Supports EIP-4337, Paymasters, and Gas Sponsorship
 * Allows users to pay gas with ERC20 tokens or have gas sponsored
 */

const ethers = require('ethers');
const axios = require('axios');

class GasAbstractionModule {
    constructor(config) {
        this.provider = new ethers.providers.JsonRpcProvider(config.rpcUrl);
        this.bundlerUrl = config.bundlerUrl; // EIP-4337 bundler
        this.paymasterUrl = config.paymasterUrl; // Paymaster service
        
        // Account abstraction contracts
        this.entryPointAddress = config.entryPointAddress || '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789';
        this.accountFactoryAddress = config.accountFactoryAddress;
        this.paymasterAddress = config.paymasterAddress;
        
        // EIP-4337 ABIs
        this.entryPointABI = [
            'function handleOps(tuple(address sender, uint256 nonce, bytes initCode, bytes callData, uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas, bytes paymasterAndData, bytes signature)[] ops, address payable beneficiary) external',
            'function getUserOpHash(tuple(address sender, uint256 nonce, bytes initCode, bytes callData, uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas, bytes paymasterAndData, bytes signature) userOp) external view returns (bytes32)',
            'function getNonce(address sender, uint192 key) external view returns (uint256)'
        ];
        
        this.paymasterABI = [
            'function validatePaymasterUserOp(tuple(address sender, uint256 nonce, bytes initCode, bytes callData, uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas, bytes paymasterAndData, bytes signature) userOp, bytes32 userOpHash, uint256 maxCost) external returns (bytes context, uint256 validationData)',
            'function postOp(uint8 mode, bytes context, uint256 actualGasCost) external'
        ];
        
        this.entryPoint = new ethers.Contract(
            this.entryPointAddress,
            this.entryPointABI,
            this.provider
        );
    }
    
    /**
     * Create UserOperation for EIP-4337
     */
    async createUserOperation(sender, to, value, data, usePaymaster = false) {
        try {
            const nonce = await this.entryPoint.getNonce(sender, 0);
            const feeData = await this.provider.getFeeData();
            
            const userOp = {
                sender: sender,
                nonce: nonce,
                initCode: '0x', // Empty if account already deployed
                callData: data,
                callGasLimit: 200000,
                verificationGasLimit: 150000,
                preVerificationGas: 21000,
                maxFeePerGas: feeData.maxFeePerGas,
                maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
                paymasterAndData: usePaymaster ? await this.getPaymasterData(sender, to, data) : '0x',
                signature: '0x' // Will be filled after signing
            };
            
            return {
                success: true,
                userOp: userOp
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get paymaster data for sponsored transaction
     */
    async getPaymasterData(sender, to, data) {
        try {
            if (!this.paymasterUrl) {
                return '0x';
            }
            
            const response = await axios.post(this.paymasterUrl, {
                method: 'pm_sponsorUserOperation',
                params: [{
                    sender: sender,
                    to: to,
                    data: data
                }]
            });
            
            return response.data.result.paymasterAndData;
            
        } catch (error) {
            console.error('Paymaster request failed:', error);
            return '0x';
        }
    }
    
    /**
     * Send UserOperation via bundler
     */
    async sendUserOperation(userOp, signer) {
        try {
            // Get UserOp hash
            const userOpHash = await this.entryPoint.getUserOpHash(userOp);
            
            // Sign the UserOp
            const signature = await signer.signMessage(ethers.utils.arrayify(userOpHash));
            userOp.signature = signature;
            
            // Send to bundler
            const response = await axios.post(this.bundlerUrl, {
                jsonrpc: '2.0',
                id: 1,
                method: 'eth_sendUserOperation',
                params: [userOp, this.entryPointAddress]
            });
            
            const userOpHash = response.data.result;
            
            console.log(`UserOperation submitted: ${userOpHash}`);
            
            // Wait for UserOp to be mined
            const receipt = await this.waitForUserOperation(userOpHash);
            
            return {
                success: true,
                userOpHash: userOpHash,
                receipt: receipt
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Wait for UserOperation to be mined
     */
    async waitForUserOperation(userOpHash, maxRetries = 30) {
        for (let i = 0; i < maxRetries; i++) {
            try {
                const response = await axios.post(this.bundlerUrl, {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_getUserOperationReceipt',
                    params: [userOpHash]
                });
                
                if (response.data.result) {
                    return response.data.result;
                }
                
                await new Promise(resolve => setTimeout(resolve, 2000));
                
            } catch (error) {
                if (i === maxRetries - 1) throw error;
            }
        }
        
        throw new Error('UserOperation not mined within timeout');
    }
    
    /**
     * Deploy mixer with gas sponsorship
     */
    async deployMixerGasless(mixerFactoryAddress, signer, accountAddress) {
        try {
            const mixerInterface = new ethers.utils.Interface([
                'function deployMyMixer() external payable returns (address)'
            ]);
            
            const deployData = mixerInterface.encodeFunctionData('deployMyMixer');
            
            // Create UserOperation
            const userOpResult = await this.createUserOperation(
                accountAddress,
                mixerFactoryAddress,
                ethers.utils.parseEther('1'),
                deployData,
                true // Use paymaster
            );
            
            if (!userOpResult.success) {
                return userOpResult;
            }
            
            // Send via bundler
            return await this.sendUserOperation(userOpResult.userOp, signer);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Deploy vault with gas sponsorship
     */
    async deployVaultGasless(vaultFactoryAddress, signer, accountAddress, customSalt = null) {
        try {
            const salt = customSalt || ethers.utils.hexlify(ethers.utils.randomBytes(32));
            
            const vaultInterface = new ethers.utils.Interface([
                'function deployVault(bytes32 salt) external payable returns (address)'
            ]);
            
            const deployData = vaultInterface.encodeFunctionData('deployVault', [salt]);
            
            const userOpResult = await this.createUserOperation(
                accountAddress,
                vaultFactoryAddress,
                ethers.utils.parseEther('1'),
                deployData,
                true
            );
            
            if (!userOpResult.success) {
                return userOpResult;
            }
            
            return await this.sendUserOperation(userOpResult.userOp, signer);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Pay gas with ERC20 tokens
     */
    async payGasWithToken(tokenAddress, amount, to, data, signer, accountAddress) {
        try {
            // Encode approval + transaction
            const tokenInterface = new ethers.utils.Interface([
                'function approve(address spender, uint256 amount) external returns (bool)'
            ]);
            
            const approveData = tokenInterface.encodeFunctionData('approve', [
                this.paymasterAddress,
                amount
            ]);
            
            // Create batch UserOperation
            const batchData = this.encodeBatch([
                { to: tokenAddress, data: approveData, value: 0 },
                { to: to, data: data, value: 0 }
            ]);
            
            const userOpResult = await this.createUserOperation(
                accountAddress,
                accountAddress, // Execute on account itself
                0,
                batchData,
                true
            );
            
            if (!userOpResult.success) {
                return userOpResult;
            }
            
            // Add token payment info to paymaster data
            userOpResult.userOp.paymasterAndData = await this.getTokenPaymasterData(
                tokenAddress,
                amount
            );
            
            return await this.sendUserOperation(userOpResult.userOp, signer);
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get paymaster data for ERC20 payment
     */
    async getTokenPaymasterData(tokenAddress, maxCost) {
        try {
            if (!this.paymasterUrl) {
                return '0x';
            }
            
            const response = await axios.post(this.paymasterUrl, {
                method: 'pm_sponsorUserOperationWithToken',
                params: [{
                    token: tokenAddress,
                    maxCost: maxCost.toString()
                }]
            });
            
            return response.data.result.paymasterAndData;
            
        } catch (error) {
            console.error('Token paymaster request failed:', error);
            return '0x';
        }
    }
    
    /**
     * Encode batch execution
     */
    encodeBatch(operations) {
        const batchInterface = new ethers.utils.Interface([
            'function executeBatch(address[] targets, uint256[] values, bytes[] callDatas) external'
        ]);
        
        const targets = operations.map(op => op.to);
        const values = operations.map(op => op.value || 0);
        const callDatas = operations.map(op => op.data);
        
        return batchInterface.encodeFunctionData('executeBatch', [targets, values, callDatas]);
    }
    
    /**
     * Estimate gas for UserOperation
     */
    async estimateUserOperationGas(userOp) {
        try {
            const response = await axios.post(this.bundlerUrl, {
                jsonrpc: '2.0',
                id: 1,
                method: 'eth_estimateUserOperationGas',
                params: [userOp, this.entryPointAddress]
            });
            
            return {
                success: true,
                gasEstimate: response.data.result
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get gas price with discount (if paymaster offers)
     */
    async getDiscountedGasPrice() {
        try {
            if (!this.paymasterUrl) {
                const feeData = await this.provider.getFeeData();
                return {
                    success: true,
                    maxFeePerGas: feeData.maxFeePerGas.toString(),
                    maxPriorityFeePerGas: feeData.maxPriorityFeePerGas.toString(),
                    discount: 0
                };
            }
            
            const response = await axios.post(this.paymasterUrl, {
                method: 'pm_getGasPrice'
            });
            
            return {
                success: true,
                ...response.data.result
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Check paymaster balance/allowance
     */
    async checkPaymasterStatus() {
        try {
            if (!this.paymasterUrl) {
                return {
                    success: false,
                    error: 'No paymaster configured'
                };
            }
            
            const response = await axios.post(this.paymasterUrl, {
                method: 'pm_getPaymasterStatus'
            });
            
            return {
                success: true,
                status: response.data.result
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = GasAbstractionModule;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY',
        bundlerUrl: 'https://bundler.example.com',
        paymasterUrl: 'https://paymaster.example.com',
        entryPointAddress: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789',
        paymasterAddress: '0xPaymasterAddress'
    };
    
    const gasModule = new GasAbstractionModule(config);
    
    // Example: Deploy mixer with sponsored gas
    const signer = new ethers.Wallet('PRIVATE_KEY');
    gasModule.deployMixerGasless(
        '0xMixerFactory',
        signer,
        '0xAccountAddress'
    ).then(result => {
        console.log('Gasless deployment:', result);
    });
}
