/**
 * Contract Controller Module for My Money Factory
 * Handles all interactions with Mixer and Vault contracts
 * Supports both mixer_factory_v2.sol and vault_factoryV2.sol
 */

const ethers = require('ethers');

class ContractController {
    constructor(config) {
        // Setup provider and signer
        if (config.privateKey) {
            this.provider = new ethers.providers.JsonRpcProvider(config.rpcUrl);
            this.signer = new ethers.Wallet(config.privateKey, this.provider);
        } else {
            this.provider = new ethers.providers.Web3Provider(window.ethereum);
            this.signer = this.provider.getSigner();
        }
        
        // Contract addresses
        this.mixerFactoryAddress = config.mixerFactoryAddress;
        this.vaultFactoryAddress = config.vaultFactoryAddress;
        
        // Mixer Factory ABI
        this.mixerFactoryABI = [
            "function deployMyMixer() external payable returns (address)",
            "function deployMixerForUser(address user) external payable returns (address)",
            "function batchDeployMixers(address[] calldata users) external payable returns (address[] memory)",
            "function getUserMixers(address) external view returns (address[])",
            "function getMixerForUser(address user) external view returns (address)",
            "function getTotalMixers() external view returns (uint256)",
            "function deploymentFee() external view returns (uint256)",
            "function getFactoryInfo() external view returns (address,address,address,address,address,uint256,bool,uint256)",
            "event MixerDeployed(address indexed user, address indexed mixer, uint256 timestamp)"
        ];
        
        // Vault Factory ABI
        this.vaultFactoryABI = [
            "function deployVault(bytes32 salt) external payable returns (address)",
            "function batchDeployVaults(bytes32[] calldata salts) external payable returns (address[] memory)",
            "function getUserVaults(address user) external view returns (address[] memory)",
            "function getTotalVaults() external view returns (uint256)",
            "function getUserVaultCount(address user) external view returns (uint256)",
            "function getBatchCost(uint256 vaultCount) external pure returns (uint256)",
            "function computeVaultAddress(bytes32 salt) external view returns (address)",
            "event VaultDeployed(address indexed vault, address indexed owner, bytes32 salt, uint256 feePaid)"
        ];
        
        // Personal Mixer ABI
        this.mixerABI = [
            "function deposit(bytes32 commitment) external payable",
            "function withdraw(bytes proof, bytes32 root, bytes32 nullifierHash, address recipient, address relayer, uint256 fee, uint256 refund) external payable",
            "function denomination() external view returns (uint256)",
            "function levels() external view returns (uint32)",
            "function nextIndex() external view returns (uint32)",
            "function owner() external view returns (address)",
            "function isKnownRoot(bytes32 root) external view returns (bool)",
            "function nullifierHashes(bytes32) external view returns (bool)",
            "event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp)",
            "event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee)"
        ];
        
        // Vault ABI
        this.vaultABI = [
            "function deposit(address token, uint256 amount, bytes32 commitment) external payable",
            "function withdraw(address token, uint256 amount, address recipient, bytes32 nullifier) external",
            "function transfer(bytes32 nullifierIn, bytes32 commitmentOut) external",
            "function addSupportedToken(address token) external",
            "function supportedTokens(address) external view returns (bool)",
            "function owner() external view returns (address)",
            "function root() external view returns (bytes32)",
            "function nextIndex() external view returns (uint256)",
            "event Deposit(bytes32 indexed commitment, uint256 leafIndex, uint256 timestamp)",
            "event Withdrawal(bytes32 indexed nullifier, address indexed recipient, address token, uint256 amount)",
            "event Transfer(bytes32 indexed nullifierIn, bytes32 indexed commitmentOut)"
        ];
        
        // Create contract instances
        this.mixerFactory = new ethers.Contract(
            this.mixerFactoryAddress,
            this.mixerFactoryABI,
            this.signer
        );
        
        this.vaultFactory = new ethers.Contract(
            this.vaultFactoryAddress,
            this.vaultFactoryABI,
            this.signer
        );
    }
    
    // ============ MIXER FACTORY METHODS ============
    
    /**
     * Deploy a personal mixer
     */
    async deployMixer(gasLimit = 5000000) {
        try {
            const fee = await this.mixerFactory.deploymentFee();
            console.log(`Deploying mixer with fee: ${ethers.utils.formatEther(fee)} ETH`);
            
            const tx = await this.mixerFactory.deployMyMixer({
                value: fee,
                gasLimit: gasLimit
            });
            
            console.log(`Transaction sent: ${tx.hash}`);
            const receipt = await tx.wait();
            
            // Extract mixer address from events
            const event = receipt.events?.find(e => e.event === 'MixerDeployed');
            const mixerAddress = event?.args?.mixer;
            
            console.log(`Mixer deployed successfully at: ${mixerAddress}`);
            return {
                success: true,
                mixerAddress: mixerAddress,
                txHash: receipt.transactionHash,
                blockNumber: receipt.blockNumber
            };
            
        } catch (error) {
            console.error('Failed to deploy mixer:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Deploy mixer for another user
     */
    async deployMixerForUser(userAddress, gasLimit = 5000000) {
        try {
            const fee = await this.mixerFactory.deploymentFee();
            
            const tx = await this.mixerFactory.deployMixerForUser(userAddress, {
                value: fee,
                gasLimit: gasLimit
            });
            
            const receipt = await tx.wait();
            const event = receipt.events?.find(e => e.event === 'MixerDeployed');
            const mixerAddress = event?.args?.mixer;
            
            return {
                success: true,
                user: userAddress,
                mixerAddress: mixerAddress,
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Batch deploy mixers for multiple users
     */
    async batchDeployMixers(userAddresses, gasLimit = 8000000) {
        try {
            const fee = await this.mixerFactory.deploymentFee();
            const totalFee = fee.mul(userAddresses.length);
            
            console.log(`Batch deploying ${userAddresses.length} mixers`);
            console.log(`Total fee: ${ethers.utils.formatEther(totalFee)} ETH`);
            
            const tx = await this.mixerFactory.batchDeployMixers(userAddresses, {
                value: totalFee,
                gasLimit: gasLimit
            });
            
            const receipt = await tx.wait();
            
            // Extract all deployed mixer addresses
            const events = receipt.events?.filter(e => e.event === 'MixerDeployed') || [];
            const mixers = events.map(e => ({
                user: e.args.user,
                mixer: e.args.mixer
            }));
            
            return {
                success: true,
                count: mixers.length,
                mixers: mixers,
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get user's mixers
     */
    async getUserMixers(userAddress) {
        try {
            const mixers = await this.mixerFactory.getUserMixers(userAddress);
            return {
                success: true,
                user: userAddress,
                mixers: mixers,
                count: mixers.length
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get total mixers deployed
     */
    async getTotalMixers() {
        try {
            const total = await this.mixerFactory.getTotalMixers();
            return {
                success: true,
                total: total.toString()
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get mixer deployment fee
     */
    async getMixerDeploymentFee() {
        try {
            const fee = await this.mixerFactory.deploymentFee();
            return {
                success: true,
                fee: ethers.utils.formatEther(fee),
                feeWei: fee.toString()
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    // ============ VAULT FACTORY METHODS ============
    
    /**
     * Deploy a single vault
     */
    async deployVault(customSalt = null, gasLimit = 5000000) {
        try {
            const salt = customSalt || ethers.utils.hexlify(ethers.utils.randomBytes(32));
            const fee = ethers.utils.parseEther('1'); // 1 ETH
            
            console.log(`Deploying vault with salt: ${salt}`);
            
            const tx = await this.vaultFactory.deployVault(salt, {
                value: fee,
                gasLimit: gasLimit
            });
            
            const receipt = await tx.wait();
            const event = receipt.events?.find(e => e.event === 'VaultDeployed');
            const vaultAddress = event?.args?.vault;
            
            console.log(`Vault deployed at: ${vaultAddress}`);
            
            return {
                success: true,
                vaultAddress: vaultAddress,
                salt: salt,
                feePaid: '1',
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Batch deploy vaults
     */
    async batchDeployVaults(count, gasLimit = 8000000) {
        try {
            // Generate random salts
            const salts = [];
            for (let i = 0; i < count; i++) {
                salts.push(ethers.utils.hexlify(ethers.utils.randomBytes(32)));
            }
            
            const feePerVault = ethers.utils.parseEther('0.8');
            const totalFee = feePerVault.mul(count);
            
            console.log(`Batch deploying ${count} vaults`);
            console.log(`Total fee: ${ethers.utils.formatEther(totalFee)} ETH`);
            
            const tx = await this.vaultFactory.batchDeployVaults(salts, {
                value: totalFee,
                gasLimit: gasLimit
            });
            
            const receipt = await tx.wait();
            const event = receipt.events?.find(e => e.event === 'BatchVaultDeployed');
            const vaults = event?.args?.vaults || [];
            
            return {
                success: true,
                count: vaults.length,
                vaults: vaults,
                totalFee: ethers.utils.formatEther(totalFee),
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get user's vaults
     */
    async getUserVaults(userAddress) {
        try {
            const vaults = await this.vaultFactory.getUserVaults(userAddress);
            return {
                success: true,
                user: userAddress,
                vaults: vaults,
                count: vaults.length
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Compute vault address before deployment
     */
    async computeVaultAddress(salt) {
        try {
            const address = await this.vaultFactory.computeVaultAddress(salt);
            return {
                success: true,
                salt: salt,
                predictedAddress: address
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    // ============ PERSONAL MIXER METHODS ============
    
    /**
     * Get mixer instance
     */
    getMixer(mixerAddress) {
        return new ethers.Contract(mixerAddress, this.mixerABI, this.signer);
    }
    
    /**
     * Deposit to mixer
     */
    async depositToMixer(mixerAddress, commitment, denomination) {
        try {
            const mixer = this.getMixer(mixerAddress);
            
            const tx = await mixer.deposit(commitment, {
                value: ethers.utils.parseEther(denomination.toString()),
                gasLimit: 2000000
            });
            
            const receipt = await tx.wait();
            const event = receipt.events?.find(e => e.event === 'Deposit');
            
            return {
                success: true,
                commitment: commitment,
                leafIndex: event?.args?.leafIndex?.toString(),
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Withdraw from mixer
     */
    async withdrawFromMixer(mixerAddress, proof, root, nullifierHash, recipient, relayer, fee, refund) {
        try {
            const mixer = this.getMixer(mixerAddress);
            
            const tx = await mixer.withdraw(
                proof,
                root,
                nullifierHash,
                recipient,
                relayer,
                fee,
                refund,
                { gasLimit: 3000000 }
            );
            
            const receipt = await tx.wait();
            
            return {
                success: true,
                recipient: recipient,
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get mixer info
     */
    async getMixerInfo(mixerAddress) {
        try {
            const mixer = this.getMixer(mixerAddress);
            
            const [denomination, levels, nextIndex, owner] = await Promise.all([
                mixer.denomination(),
                mixer.levels(),
                mixer.nextIndex(),
                mixer.owner()
            ]);
            
            return {
                success: true,
                address: mixerAddress,
                denomination: ethers.utils.formatEther(denomination),
                levels: levels.toString(),
                nextIndex: nextIndex.toString(),
                owner: owner
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    // ============ VAULT METHODS ============
    
    /**
     * Get vault instance
     */
    getVault(vaultAddress) {
        return new ethers.Contract(vaultAddress, this.vaultABI, this.signer);
    }
    
    /**
     * Deposit to vault
     */
    async depositToVault(vaultAddress, token, amount, commitment) {
        try {
            const vault = this.getVault(vaultAddress);
            
            const tx = await vault.deposit(token, amount, commitment, {
                value: ethers.utils.parseEther('0.001'), // Deposit fee
                gasLimit: 2000000
            });
            
            const receipt = await tx.wait();
            const event = receipt.events?.find(e => e.event === 'Deposit');
            
            return {
                success: true,
                commitment: commitment,
                leafIndex: event?.args?.leafIndex?.toString(),
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Withdraw from vault
     */
    async withdrawFromVault(vaultAddress, token, amount, recipient, nullifier) {
        try {
            const vault = this.getVault(vaultAddress);
            
            const tx = await vault.withdraw(token, amount, recipient, nullifier, {
                gasLimit: 2000000
            });
            
            const receipt = await tx.wait();
            
            return {
                success: true,
                recipient: recipient,
                token: token,
                amount: ethers.utils.formatEther(amount),
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Add supported token to vault
     */
    async addSupportedToken(vaultAddress, tokenAddress) {
        try {
            const vault = this.getVault(vaultAddress);
            
            const tx = await vault.addSupportedToken(tokenAddress, {
                gasLimit: 100000
            });
            
            const receipt = await tx.wait();
            
            return {
                success: true,
                vault: vaultAddress,
                token: tokenAddress,
                txHash: receipt.transactionHash
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get vault info
     */
    async getVaultInfo(vaultAddress) {
        try {
            const vault = this.getVault(vaultAddress);
            
            const [root, nextIndex, owner] = await Promise.all([
                vault.root(),
                vault.nextIndex(),
                vault.owner()
            ]);
            
            return {
                success: true,
                address: vaultAddress,
                root: root,
                nextIndex: nextIndex.toString(),
                owner: owner
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

// Export the module
module.exports = ContractController;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY',
        privateKey: 'YOUR_PRIVATE_KEY',
        mixerFactoryAddress: '0x1234567890123456789012345678901234567890',
        vaultFactoryAddress: '0x3456789012345678901234567890123456789012'
    };
    
    const controller = new ContractController(config);
    
    // Example: Deploy a mixer
    controller.deployMixer().then(result => {
        console.log('Deploy result:', result);
    });
}
