/**
 * Oracle Module
 * Supports Chainlink, Pyth Network, and Custom Oracles
 * Provides price feeds, random numbers, and external data
 */

const ethers = require('ethers');
const axios = require('axios');

class OracleModule {
    constructor(config) {
        this.provider = new ethers.providers.JsonRpcProvider(config.rpcUrl);
        
        // Chainlink configuration
        this.chainlinkFeeds = config.chainlinkFeeds || {
            'ETH/USD': '0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419',
            'BTC/USD': '0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c',
            'USDC/USD': '0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6'
        };
        
        // Pyth configuration
        this.pythAddress = config.pythAddress || '0x4305FB66699C3B2702D4d05CF36551390A4c69C6';
        this.pythPriceIds = config.pythPriceIds || {
            'ETH/USD': '0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace',
            'BTC/USD': '0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43'
        };
        
        // VRF (Verifiable Random Function) for randomness
        this.vrfCoordinator = config.vrfCoordinator;
        this.vrfKeyHash = config.vrfKeyHash;
        this.vrfSubscriptionId = config.vrfSubscriptionId;
        
        // Chainlink ABIs
        this.chainlinkABI = [
            'function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)',
            'function decimals() external view returns (uint8)',
            'function description() external view returns (string)'
        ];
        
        // Pyth ABI
        this.pythABI = [
            'function getPrice(bytes32 id) external view returns (int64 price, uint64 conf, int32 expo, uint256 publishTime)',
            'function getPriceUnsafe(bytes32 id) external view returns (int64 price, uint64 conf, int32 expo, uint256 publishTime)',
            'function updatePriceFeeds(bytes[] calldata updateData) external payable'
        ];
        
        // VRF ABI
        this.vrfABI = [
            'function requestRandomWords(bytes32 keyHash, uint64 subId, uint16 minimumRequestConfirmations, uint32 callbackGasLimit, uint32 numWords) external returns (uint256 requestId)',
            'event RandomWordsRequested(bytes32 indexed keyHash, uint256 requestId, uint256 preSeed, uint64 indexed subId, uint16 minimumRequestConfirmations, uint32 callbackGasLimit, uint32 numWords, address indexed sender)'
        ];
        
        this.pythContract = new ethers.Contract(this.pythAddress, this.pythABI, this.provider);
    }
    
    // ============ CHAINLINK PRICE FEEDS ============
    
    /**
     * Get ETH price from Chainlink
     */
    async getETHPrice() {
        return await this.getChainlinkPrice('ETH/USD');
    }
    
    /**
     * Get price from Chainlink feed
     */
    async getChainlinkPrice(pair) {
        try {
            const feedAddress = this.chainlinkFeeds[pair];
            if (!feedAddress) {
                throw new Error(`No Chainlink feed for ${pair}`);
            }
            
            const priceFeed = new ethers.Contract(feedAddress, this.chainlinkABI, this.provider);
            
            const [roundId, answer, startedAt, updatedAt, answeredInRound] = await priceFeed.latestRoundData();
            const decimals = await priceFeed.decimals();
            const description = await priceFeed.description();
            
            const price = parseFloat(ethers.utils.formatUnits(answer, decimals));
            
            return {
                success: true,
                pair: pair,
                price: price,
                decimals: decimals,
                updatedAt: new Date(updatedAt.toNumber() * 1000).toISOString(),
                roundId: roundId.toString(),
                description: description
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get multiple prices at once
     */
    async getChainlinkPrices(pairs) {
        try {
            const promises = pairs.map(pair => this.getChainlinkPrice(pair));
            const results = await Promise.all(promises);
            
            const prices = {};
            results.forEach(result => {
                if (result.success) {
                    prices[result.pair] = result.price;
                }
            });
            
            return {
                success: true,
                prices: prices,
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Convert ETH amount to USD
     */
    async ethToUSD(ethAmount) {
        try {
            const priceResult = await this.getETHPrice();
            if (!priceResult.success) {
                return priceResult;
            }
            
            const usdValue = ethAmount * priceResult.price;
            
            return {
                success: true,
                ethAmount: ethAmount,
                usdValue: usdValue,
                ethPrice: priceResult.price
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Convert USD amount to ETH
     */
    async usdToETH(usdAmount) {
        try {
            const priceResult = await this.getETHPrice();
            if (!priceResult.success) {
                return priceResult;
            }
            
            const ethAmount = usdAmount / priceResult.price;
            
            return {
                success: true,
                usdAmount: usdAmount,
                ethAmount: ethAmount,
                ethPrice: priceResult.price
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    // ============ PYTH NETWORK ============
    
    /**
     * Get price from Pyth Network
     */
    async getPythPrice(pair) {
        try {
            const priceId = this.pythPriceIds[pair];
            if (!priceId) {
                throw new Error(`No Pyth price ID for ${pair}`);
            }
            
            const priceData = await this.pythContract.getPriceUnsafe(priceId);
            
            const price = parseFloat(priceData.price) * Math.pow(10, priceData.expo);
            const confidence = parseFloat(priceData.conf) * Math.pow(10, priceData.expo);
            
            return {
                success: true,
                pair: pair,
                price: price,
                confidence: confidence,
                publishTime: new Date(priceData.publishTime.toNumber() * 1000).toISOString(),
                exponent: priceData.expo
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Update Pyth price feeds
     */
    async updatePythPrices(priceUpdateData, signer) {
        try {
            const pythWithSigner = this.pythContract.connect(signer);
            
            const tx = await pythWithSigner.updatePriceFeeds(priceUpdateData, {
                value: ethers.utils.parseEther('0.001') // Update fee
            });
            
            const receipt = await tx.wait();
            
            return {
                success: true,
                txHash: receipt.transactionHash,
                message: 'Pyth prices updated'
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get Pyth price update data from Hermes API
     */
    async getPythUpdateData(priceIds) {
        try {
            const idsQuery = priceIds.join('&ids[]=');
            const response = await axios.get(
                `https://hermes.pyth.network/api/latest_vaas?ids[]=${idsQuery}`
            );
            
            return {
                success: true,
                updateData: response.data
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    // ============ CHAINLINK VRF (RANDOM NUMBERS) ============
    
    /**
     * Request random words from Chainlink VRF
     */
    async requestRandomWords(numWords, signer, callbackGasLimit = 100000) {
        try {
            if (!this.vrfCoordinator) {
                throw new Error('VRF Coordinator not configured');
            }
            
            const vrf = new ethers.Contract(this.vrfCoordinator, this.vrfABI, signer);
            
            const tx = await vrf.requestRandomWords(
                this.vrfKeyHash,
                this.vrfSubscriptionId,
                3, // confirmations
                callbackGasLimit,
                numWords
            );
            
            const receipt = await tx.wait();
            const event = receipt.events?.find(e => e.event === 'RandomWordsRequested');
            const requestId = event?.args?.requestId;
            
            return {
                success: true,
                requestId: requestId.toString(),
                txHash: receipt.transactionHash,
                message: 'Random words requested'
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    // ============ CUSTOM ORACLE ============
    
    /**
     * Get data from custom oracle endpoint
     */
    async getCustomOracleData(endpoint, params = {}) {
        try {
            const response = await axios.get(endpoint, { params });
            
            return {
                success: true,
                data: response.data,
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Post data to custom oracle
     */
    async postCustomOracleData(endpoint, data) {
        try {
            const response = await axios.post(endpoint, data);
            
            return {
                success: true,
                response: response.data
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    // ============ UTILITY FUNCTIONS ============
    
    /**
     * Get gas price in USD
     */
    async getGasPriceUSD(gasLimit = 21000) {
        try {
            const [feeData, ethPrice] = await Promise.all([
                this.provider.getFeeData(),
                this.getETHPrice()
            ]);
            
            if (!ethPrice.success) {
                return ethPrice;
            }
            
            const gasCostWei = feeData.maxFeePerGas.mul(gasLimit);
            const gasCostETH = parseFloat(ethers.utils.formatEther(gasCostWei));
            const gasCostUSD = gasCostETH * ethPrice.price;
            
            return {
                success: true,
                gasLimit: gasLimit,
                gasPriceGwei: parseFloat(ethers.utils.formatUnits(feeData.maxFeePerGas, 'gwei')),
                gasCostETH: gasCostETH,
                gasCostUSD: gasCostUSD,
                ethPrice: ethPrice.price
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Check if price is within acceptable range
     */
    async isPriceInRange(pair, minPrice, maxPrice) {
        try {
            const priceResult = await this.getChainlinkPrice(pair);
            if (!priceResult.success) {
                return priceResult;
            }
            
            const inRange = priceResult.price >= minPrice && priceResult.price <= maxPrice;
            
            return {
                success: true,
                pair: pair,
                currentPrice: priceResult.price,
                minPrice: minPrice,
                maxPrice: maxPrice,
                inRange: inRange
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Get price with multiple oracle sources (average)
     */
    async getAveragePrice(pair) {
        try {
            const [chainlink, pyth] = await Promise.all([
                this.getChainlinkPrice(pair),
                this.getPythPrice(pair)
            ]);
            
            const prices = [];
            if (chainlink.success) prices.push(chainlink.price);
            if (pyth.success) prices.push(pyth.price);
            
            if (prices.length === 0) {
                throw new Error('No oracle sources available');
            }
            
            const average = prices.reduce((a, b) => a + b, 0) / prices.length;
            const deviation = Math.max(...prices) - Math.min(...prices);
            
            return {
                success: true,
                pair: pair,
                averagePrice: average,
                sources: prices.length,
                priceDeviation: deviation,
                chainlinkPrice: chainlink.success ? chainlink.price : null,
                pythPrice: pyth.success ? pyth.price : null
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Monitor price and trigger callback when condition met
     */
    async monitorPrice(pair, condition, callback, interval = 60000) {
        console.log(`Monitoring ${pair} with condition: ${condition}`);
        
        const checkPrice = async () => {
            const result = await this.getChainlinkPrice(pair);
            if (result.success) {
                const conditionMet = eval(`${result.price} ${condition}`);
                if (conditionMet) {
                    callback(result);
                    clearInterval(monitor);
                }
            }
        };
        
        const monitor = setInterval(checkPrice, interval);
        return monitor;
    }
    
    /**
     * Get historical price data (if supported)
     */
    async getHistoricalPrices(pair, fromTimestamp, toTimestamp) {
        try {
            // This would integrate with a service that provides historical data
            const response = await axios.get('https://api.example.com/historical', {
                params: {
                    pair: pair,
                    from: fromTimestamp,
                    to: toTimestamp
                }
            });
            
            return {
                success: true,
                pair: pair,
                data: response.data
            };
            
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = OracleModule;

// Example usage
if (require.main === module) {
    const config = {
        rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY',
        vrfCoordinator: '0x271682DEB8C4E0901D1a1550aD2e64D568E69909',
        vrfKeyHash: '0x8af398995b04c28e9951adb9721ef74c74f93e6a478f39e7e0777be13527e7ef',
        vrfSubscriptionId: 1
    };
    
    const oracle = new OracleModule(config);
    
    // Example: Get ETH price
    oracle.getETHPrice().then(result => {
        console.log('ETH Price:', result);
    });
    
    // Example: Convert 1 ETH to USD
    oracle.ethToUSD(1).then(result => {
        console.log('1 ETH =', result.usdValue, 'USD');
    });
    
    // Example: Get gas cost in USD
    oracle.getGasPriceUSD(200000).then(result => {
        console.log('Gas cost:', result.gasCostUSD, 'USD');
    });
}
