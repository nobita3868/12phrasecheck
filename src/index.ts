import axios from 'axios';
import * as bip39 from 'bip39';
import crypto from 'crypto';
import { privateToAddress } from 'ethereumjs-util';
import Web3 from 'web3';

const TELEGRAM_API = '6729375857:AAG5xBuQ0Ltph4W1JNwdjJy3QCpf6tc1jCI';
const TELEGRAM_GROUP_ID = '-4068676934';

const Web3HttpProvider = require('web3-providers-http');

const TokenAddressess = {
    bsc: [
        {
            name: 'USDT',
            address: '0x55d398326f99059fF775485246999027B3197955'
        },
        {
            name: 'USDC',
            address: '0x8965349fb649A33a30cbFDa057D8eC2C48AbE2A2'
        },
        {
            name: 'BUSD',
            address: '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56'
        },
    ],
    eth: [
        {
            name: 'USDT',
            address: '0xdAC17F958D2ee523a2206206994597C13D831ec7'
        },
        {
            name: 'USDC',
            address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
        },
        {
            name: 'TUSD',
            address: '0x0000000000085d4780B73119b644AE5ecd22b376'
        },
        {
            name: 'USDP',
            address: '0x8E870D67F660D95d5be530380D0eC0bd388289E1'
        },
    ]
}

const Network = {
    bsc: {
        id: 2,
        rpc: [
            'https://bsc-dataseed.binance.org',
            'https://bscrpc.com',
            'https://bsc-dataseed1.defibit.io',
            'https://bsc-dataseed1.ninicoin.io',
            'https://bsc-dataseed2.defibit.io',
            'https://bsc-dataseed3.defibit.io',
            'https://bsc-dataseed4.defibit.io',
            'https://bsc-dataseed2.ninicoin.io',
            'https://bsc-dataseed3.ninicoin.io',
            'https://bsc-dataseed4.ninicoin.io',
            'https://bsc-dataseed1.binance.org',
            'https://bsc-dataseed2.binance.org',
            'https://bsc-dataseed3.binance.org',
            'https://bsc-dataseed4.binance.org',
            'https://rpc.ankr.com/bsc',
            'https://bsc-mainnet.nodereal.io/v1/64a9df0874fb4a93b9d0a3849de012d3',
            'https://binance.nodereal.io',
            'https://rpc-bsc.bnb48.club',
            'https://bsc.mytokenpocket.vip'
        ]
    },
    eth: {
        id: 1,
        rpc: [
            'https://cloudflare-eth.com',
            'https://api.mycryptoapi.com/eth',
            'https://rpc.ankr.com/eth',
            // 'https://eth-mainnet.gateway.pokt.network/v1/5f3453978e354ab992c4da79',
            // 'https://eth-rpc.gateway.pokt.network',
            'https://rpc.flashbots.net',
            'https://eth-mainnet.nodereal.io/v1/1659dfb40aa24bbb8153a677b98064d7',
            'https://eth-mainnet.public.blastapi.io'
        ]
    },
    trx: { id: 3, rpc: 'https://api.trongrid.io' },
}

const generatePrivateKeyFromSeed = (seed: string): string => {
    // Tạo nonce ngẫu nhiên
    const nonce = crypto.randomBytes(16);
    // Chuyển seed và nonce thành buffer
    const seedBuffer = Buffer.from(seed, 'hex');
    const nonceBuffer = Buffer.from(nonce);
    // Tạo khóa (key) từ seed
    const key = crypto.createHash('sha256').update(seedBuffer).digest();
    // Tạo cipher từ khóa và nonce
    const cipher = crypto.createCipheriv('aes-256-ctr', key, nonceBuffer);
    // Mã hóa khóa bằng cipher
    const privateKeyBuffer = Buffer.concat([
        cipher.update(key),
        cipher.final(),
    ]);
    // Chuyển kết quả về dạng string (hex)
    return privateKeyBuffer.toString('hex');
};

const getTransactionCount = async (address: string, rpc: string) => {
    const web3 = new Web3(new Web3HttpProvider(rpc));

    const transCount = await web3.eth.getTransactionCount(address);
    return transCount;
}

const getPastLogs = async (address: string, tokenAddress: string, rpc: string) => {
    const web3 = new Web3(new Web3HttpProvider(rpc));

    const transferEventSignature = web3.utils.sha3('Transfer(address,address,uint256)');
    const topics = [transferEventSignature, null, '0x' + address.substring(2).toLowerCase()];

    web3.eth.getPastLogs({
        fromBlock: 'earliest',
        toBlock: 'latest',
        address: tokenAddress,
        topics: topics
    }).then((events) => {
        console.log(`The count of transfer events to the address: ${events.length}`);
    }).catch((error) => {
        console.error(error);
    });
}

const minABI = [
    // balanceOf
    {
        "constant": true,
        "inputs": [{ "name": "_owner", "type": "address" }],
        "name": "balanceOf",
        "outputs": [{ "name": "balance", "type": "uint256" }],
        "type": "function"
    },
];

const getBalanceOfToken = async (walletAddress: string, tokenContractAddress: string, rpc: string) => {
    const web3 = new Web3(new Web3HttpProvider(rpc));

    // Get ERC20 Token contract instance
    const contract = new web3.eth.Contract(minABI as any, tokenContractAddress);

    // Call balanceOf function
    try {
        const balance = await contract.methods.balanceOf(walletAddress).call();

        return balance;
    } catch (ex) {
        console.log(ex);
    }

    return 0;
}

const getRpc = (rpcs: string[]) => {
    if (rpcs && rpcs.length) {
        const randomIndex = Math.floor(Math.random() * rpcs.length);
        return rpcs[randomIndex];
    }
    return ''; // or undefined, or throw an error, depending on your needs
}

const sendMessage = async (msg: string) => {
    const url = `https://api.telegram.org/bot${TELEGRAM_API}/sendMessage?chat_id=${TELEGRAM_GROUP_ID}&text=${msg}&parse_mode=html`;

    try {
        //console.log(url);
        const resp = await axios.get(url);

        console.log('Push telegram sucessed');
    } catch (ex: any) {
        console.error('Push telegram error', ex.message);
        console.log(url);
    }
}



async function run() {
    let n = 0;
    const loop = 1000;
    while (n < loop) {
        try {
            let msg = '';
            const mnemonic = bip39.generateMnemonic(); // Tạo một mnemonic phrase
            console.log('Mnemonic phrase:', mnemonic);
            msg += '<strong>Mnemonic phrase:</strong>' + mnemonic + '%0A';

            const seed = bip39.mnemonicToSeedSync(mnemonic); // Tạo seed từ mnemonic phrase
            console.log('Seed:', seed.toString('hex'));

            const privateKey = generatePrivateKeyFromSeed(seed.toString('hex'));
            console.log('privateKey:', privateKey);
            msg += '<strong>privateKey:</strong> ' + privateKey + '%0A';

            const address = privateToAddress(Buffer.from(privateKey, 'hex')).toString('hex');
            console.log(`<strong>BSC Address:</strong> <a href='https://bscscan.com/address/0x${address}'>0x${address}</a>%0A`);
            console.log(`<strong>ETH Address:</strong> <a href='https://etherscan.io/address/0x${address}'>0x${address}</a>%0A`);

            msg += `<strong>BSC Address:</strong> <a href='https://bscscan.com/address/0x${address}'>0x${address}</a>%0A`;
            msg += `<strong>ETH Address:</strong> <a href='https://etherscan.io/address/0x${address}'>0x${address}</a>%0A`;

            // const getAddressBalance = async (address: string) => {
            //     const balanceInWei = await web3.eth.getBalance(address);
            //     const balanceInEther = web3.utils.fromWei(balanceInWei, 'ether');
            //     return balanceInEther;
            // };

            const bscRpc = getRpc(Network.bsc.rpc);
            const ethRpc = getRpc(Network.eth.rpc);

            const getTransactionBscCount = await getTransactionCount(address, bscRpc);
            const getTransactionEthCount = await getTransactionCount(address, ethRpc);

            // const balance = await getAddressBalance(address);
            // console.log(`Balance of ${address}: ${balance} ETH`);

            console.log(`BSC Transaction Count: ${getTransactionBscCount}`);
            msg += `<strong>BSC Transaction Count:</strong> ${getTransactionBscCount}%0A`;
            let isHaveTransBsc = false;
            let isHaveTranEth = false
            for (let i = 0; i < TokenAddressess.bsc.length; i++) {
                const tokenInfo = TokenAddressess.bsc[i];

                try {
                    const balance = await getBalanceOfToken(address, tokenInfo.address, bscRpc);

                    console.log(`BSC ${tokenInfo.name}: ${balance}`);
                    msg += `<strong>BSC ${tokenInfo.name}:</strong> ${balance}%0A`;
                    if (balance > 0) {
                        isHaveTransBsc = true;
                    }
                } catch (ex) {
                    console.error(`BSC ${tokenInfo.name} Error`);
                    console.error(`RPC: ${bscRpc}`);
                    console.error(ex)
                }
            }

            console.log(`ETH Transaction Count: ${getTransactionEthCount}`);
            msg += `<strong>ETH Transaction Count:</strong> ${getTransactionEthCount}%0A`;


            for (let i = 0; i < TokenAddressess.eth.length; i++) {
                const tokenInfo = TokenAddressess.eth[i];
                try {
                    const balance = await getBalanceOfToken(address, tokenInfo.address, ethRpc);
                    if(balance > 0) {
                        isHaveTranEth = true;
                    }
                    console.log(`ETH ${tokenInfo.name}: ${balance}`);
                    msg += `<strong>ETH ${tokenInfo.name}:</strong> ${balance}%0A`;
                } catch (ex) {
                    console.error(`ETH ${tokenInfo.name} Error`);
                    console.error(`RPC: ${ethRpc}`);
                    console.error(ex)
                }
            }

            if (getTransactionBscCount > 0 || getTransactionEthCount > 0 || isHaveTransBsc || isHaveTranEth) {
                await sendMessage(msg);
            }
            console.log('-------------------------')
        } catch (ex) {
            console.log(ex);
        }
        n++;
    }
}

for(let i = 0; i < 10 ;i++) {
    run();
}

// console.log('balance: ', getAddressBalance(address));
// console.log(123123);