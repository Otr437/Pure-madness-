/**
 * Webhook Module for My Money Factory
 * Monitors contract events and sends webhook notifications
 * Supports both Mixer Factory and Vault Factory contracts
 */

const ethers = require('ethers');
const axios = require('axios');

class WebhookModule {
    constructor(config) {
        this.provider = new ethers.providers.JsonRpcProvider(config.rpcUrl);
        this.webhookUrl = config.webhookUrl;
        
        // Contract addresses
        this.mixerFactoryAddress = config.mixerFactoryAddress;
        this.vaultFactoryAddress = config.vaultFactoryAddress;
        
        // ABIs
        this.mixerFactoryABI = [
            "event MixerDeployed(address indexed user, address indexed mixer, uint256 timestamp)",
            "event PaymentReceived(address indexed from, uint256 amount, uint256 timestamp)"
        ];
        
        this.vaultFactoryABI = [
            "event VaultDeployed(address indexed vault, address indexed owner, bytes32 salt, uint256 feePaid)",
            "event BatchVaultDeployed(address[] vaults, address indexed owner, uint256 totalFeePaid)"
        ];
        
        this.mixerABI = [
            "event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp)",
            "event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee)"
        ];
        
        this.vaultABI = [
            "event Deposit(bytes32 indexed commitment, uint256 leafIndex, uint256 timestamp)",
            "event Withdrawal(bytes32 indexed nullifier, address indexed recipient, address token, uint256 amount)",
            "event Transfer(bytes32 indexed nullifierIn, bytes32 indexed commitmentOut)"
        ];
        
        // Create contract instances
        this.mixerFactory = new ethers.Contract(
            this.mixerFactoryAddress,
            this.mixerFactoryABI,
            this.provider
        );
        
        this.vaultFactory = new ethers.Contract(
            this.vaultFactoryAddress,
            this.vaultFactoryABI,
            this.provider
        );
        
        this.isListening = false;
    }
    
    /**
     * Start listening to all contract events
     */
    async startListening() {
        if (this.isListening) {
            console.log('Already listening to events');
            return;
        }
        
        console.log('Starting webhook listener...');
        this.isListening = true;
        
        // Listen to Mixer Factory events
        this.mixerFactory.on('MixerDeployed', async (user, mixer, timestamp, event) => {
            await this.handleMixerDeployed(user, mixer, timestamp, event);
        });
        
        this.mixerFactory.on('PaymentReceived', async (from, amount, timestamp, event) => {
            await this.handlePaymentReceived(from, amount, timestamp, event);
        });
        
        // Listen to Vault Factory events
        this.vaultFactory.on('VaultDeployed', async (vault, owner, salt, feePaid, event) => {
            await this.handleVaultDeployed(vault, owner, salt, feePaid, event);
        });
        
        this.vaultFactory.on('BatchVaultDeployed', async (vaults, owner, totalFeePaid, event) => {
            await this.handleBatchVaultDeployed(vaults, owner, totalFeePaid, event);
        });
        
        console.log('Webhook listener started successfully');
        console.log(`Monitoring Mixer Factory: ${this.mixerFactoryAddress}`);
        console.log(`Monitoring Vault Factory: ${this.vaultFactoryAddress}`);
    }
    
    /**
     * Stop listening to events
     */
    stopListening() {
        if (!this.isListening) {
            console.log('Not currently listening');
            return;
        }
        
        this.mixerFactory.removeAllListeners();
        this.vaultFactory.removeAllListeners();
        this.isListening = false;
        
        console.log('Webhook listener stopped');
    }
    
    /**
     * Listen to specific mixer contract events
     */
    async listenToMixer(mixerAddress) {
        const mixer = new ethers.Contract(mixerAddress, this.mixerABI, this.provider);
        
        mixer.on('Deposit', async (commitment, leafIndex, timestamp, event) => {
            await this.sendWebhook({
                event: 'MixerDeposit',
                mixer: mixerAddress,
                commitment: commitment,
                leafIndex: leafIndex.toString(),
                timestamp: timestamp.toString(),
                txHash: event.transactionHash,
                blockNumber: event.blockNumber
            });
        });
        
        mixer.on('Withdrawal', async (to, nullifierHash, relayer, fee, event) => {
            await this.sendWebhook({
                event: 'MixerWithdrawal',
                mixer: mixerAddress,
                recipient: to,
                nullifierHash: nullifierHash,
                relayer: relayer,
                fee: ethers.utils.formatEther(fee),
                txHash: event.transactionHash,
                blockNumber: event.blockNumber
            });
        });
        
        console.log(`Now listening to Mixer: ${mixerAddress}`);
    }
    
    /**
     * Listen to specific vault contract events
     */
    async listenToVault(vaultAddress) {
        const vault = new ethers.Contract(vaultAddress, this.vaultABI, this.provider);
        
        vault.on('Deposit', async (commitment, leafIndex, timestamp, event) => {
            await this.sendWebhook({
                event: 'VaultDeposit',
                vault: vaultAddress,
                commitment: commitment,
                leafIndex: leafIndex.toString(),
                timestamp: timestamp.toString(),
                txHash: event.transactionHash,
                blockNumber: event.blockNumber
            });
        });
        
        vault.on('Withdrawal', async (nullifier, recipient, token, amount, event) => {
            await this.sendWebhook({
                event: 'VaultWithdrawal',
                vault: vaultAddress,
                nullifier: nullifier,
                recipient: recipient,
                token: token,
                amount: ethers.utils.formatEther(amount),
                txHash: event.transactionHash,
                blockNumber: event.blockNumber
            });
        });
        
        vault.on('Transfer', async (nullifierIn, commitmentOut, event) => {
            await this.sendWebhook({
                event: 'VaultTransfer',
                vault: vaultAddress,
                nullifierIn: nullifierIn,
                commitmentOut: commitmentOut,
                txHash: event.transactionHash,
                blockNumber: event.blockNumber
            });
        });
        
        console.log(`Now listening to Vault: ${vaultAddress}`);
    }
    
    /**
     * Handle Mixer Deployed event
     */
    async handleMixerDeployed(user, mixer, timestamp, event) {
        const payload = {
            event: 'MixerDeployed',
            user: user,
            mixer: mixer,
            timestamp: timestamp.toString(),
            txHash: event.transactionHash,
            blockNumber: event.blockNumber
        };
        
        await this.sendWebhook(payload);
        
        // Automatically start listening to the new mixer
        await this.listenToMixer(mixer);
    }
    
    /**
     * Handle Payment Received event
     */
    async handlePaymentReceived(from, amount, timestamp, event) {
        const payload = {
            event: 'PaymentReceived',
            from: from,
            amount: ethers.utils.formatEther(amount),
            timestamp: timestamp.toString(),
            txHash: event.transactionHash,
            blockNumber: event.blockNumber
        };
        
        await this.sendWebhook(payload);
    }
    
    /**
     * Handle Vault Deployed event
     */
    async handleVaultDeployed(vault, owner, salt, feePaid, event) {
        const payload = {
            event: 'VaultDeployed',
            vault: vault,
            owner: owner,
            salt: salt,
            feePaid: ethers.utils.formatEther(feePaid),
            txHash: event.transactionHash,
            blockNumber: event.blockNumber
        };
        
        await this.sendWebhook(payload);
        
        // Automatically start listening to the new vault
        await this.listenToVault(vault);
    }
    
    /**
     * Handle Batch Vault Deployed event
     */
    async handleBatchVaultDeployed(vaults, owner, totalFeePaid, event) {
        const payload = {
            event: 'BatchVaultDeployed',
            vaults: vaults,
            owner: owner,
            vaultCount: vaults.length,
            totalFeePaid: ethers.utils.formatEther(totalFeePaid),
            txHash: event.transactionHash,
            blockNumber: event.blockNumber
        };
        
        await this.sendWebhook(payload);
        
        // Automatically start listening to all new vaults
        for (const vault of vaults) {
            await this.listenToVault(vault);
        }
    }
    
    /**
     * Send webhook notification
     */
    async sendWebhook(payload) {
        try {
            const timestamp = new Date().toISOString();
            const webhookPayload = {
                ...payload,
                sentAt: timestamp,
                network: await this.provider.getNetwork().then(n => n.name)
            };
            
            console.log('Sending webhook:', JSON.stringify(webhookPayload, null, 2));
            
            const response = await axios.post(this.webhookUrl, webhookPayload, {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Webhook-Source': 'MyMoneyFactory'
                },
                timeout: 10000
            });
            
            console.log(`Webhook sent successfully: ${response.status}`);
            return response.data;
            
        } catch (error) {
            console.error('Failed to send webhook:', error.message);
            if (error.response) {
                console.error('Response:', error.response.data);
            }
        }
    }
    
    /**
     * Get historical events
     */
    async getHistoricalEvents(contractType, fromBlock = 0, toBlock = 'latest') {
        const contract = contractType === 'mixer' ? this.mixerFactory : this.vaultFactory;
        const events = await contract.queryFilter('*', fromBlock, toBlock);
        
        console.log(`Found ${events.length} historical ${contractType} events`);
        return events;
    }
}

// Export the module
module.exports = WebhookModule;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY',
        webhookUrl: 'https://your-webhook-endpoint.com/webhook',
        mixerFactoryAddress: '0x1234567890123456789012345678901234567890',
        vaultFactoryAddress: '0x3456789012345678901234567890123456789012'
    };
    
    const webhook = new WebhookModule(config);
    webhook.startListening();
    
    // Keep the process running
    process.on('SIGINT', () => {
        webhook.stopListening();
        process.exit();
    });
}
