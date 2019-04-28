"use strict";

const fs = require('fs');
const Web3 = require('web3');
const solc = require('solc');

class web3Operator {
  constructor(rpcUrl) {
    var web3 = new Web3(rpcUrl);
    if (web3.eth.net.isListening()) console.log('network connected!');
  }

    // account operation 
  createAccount = (random) => {
    let accountObject = web3.eth.accounts.create(random);
    return accountObject;
  }
  queryAccount = (prikey) => {
    let account = web3.eth.accounts.privateKeyToAccount(prikey);
    return account.address;
  }
  decryptAccount = async (keyStoreJson, password) => {
    let decrypted = await web3.eth.accounts.decrypt(keyStoreJson, password);
    return decrypted;
  }
  importKey = async (privateKey, password) => {
    let address = await web3.eth.personal.importRawKey(privateKey, password);
    return true;
  }
  encryptAccount = async (privateKey, password) => {
    let keyStoreJson = await web3.eth.accounts.encrypt(privateKey, password);
    return keyStoreJson;
  }
  sha3_hash = (data) => {
    let hash_data = web3.utils.sha3(JSON.stringify(data))
    return hash_data;
  }


  // general function
  Crypto = (data, exec) => {
    const crypto = require('crypto');
    const algorithm = 'aes-256-cbc';
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);


    if (exec == 'encrypt') {
      data = JSON.stringify(data);
      console.log('start encrypt');
      const enc_data = encrypt(data);
      return enc_data;
    } if (exec == 'decrypt') {
      console.log('start decrypt');
      const dec_data = decrypt(data);
      return dec_data;
    }
    return console.error('error');


    function encrypt(data) {
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      return { key: key.toString('hex'), iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
    }
    function decrypt(data) {
      const _iv = Buffer.from(data.iv, 'hex');
      const _key = Buffer.from(data.key, 'hex');
      const _encryptedData = Buffer.from(data.encryptedData, 'hex');
      const decipher = crypto.createDecipheriv(algorithm, _key, _iv);
      let decrypted = decipher.update(_encryptedData);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return decrypted.toString();
    }
  };

  sha3Hash = (data) => {
    data = JSON.stringify(data);
    const hash_data = web3.utils.sha3(data);
    return hash_data;
  };


  // contract interaction
  compiles = (contract) => {
    // load file > compile > get abi & bytecode
    console.log('read file...');
    const file = fs.readFileSync(`/contract/${contract}.sol`, 'utf8');
    console.log('compile....');

    const compiledContract = solc.compile(file);
    console.log('done');
    console.log(compiledContract);
    const bytecode = '0x' + compiledContract.contracts[`:${_contract}`].bytecode;
    const abi = compiledContract.contracts[`:${_contract}`].interface;

    const output = { contract, abi, bytecode };
    return fs.writeFile(`../contract_detail_repo/${contract}_info.json`, JSON.stringify(output), (err, file) => {
      if (!err) console.log('writed abi! ');
      else console.log(err);
      return true;
    });
  };

  privateKeyToDeploy = (contract, privateKey) => {
    UtilsContractDeploy(contract, '', '', privateKey);
  };
  accountToDeploy = (contract, from, password) => {
    UtilsContractDeploy(contract, from, password, '');
  };

  readContract = (contract, method, parameters) => {
    return UtilsContractProcess(contract, method, parameters, 0, '', '', 'read', false, 0);
  };

  accountToWriteContract = (from, contract, method, parameters, value, password) => {
    UtilsContractProcess(from, contract, method, parameters, value, '', password, 'write', false, 0);
  };
  privateKeyToWriteContract = (contract, method, parameters, value, privateKey) => {
    UtilsContractProcess('', contract, method, parameters, value, privateKey, '', 'write', false, 0);
  };

  ListeningEvent = (type, host, port) => {
    const wsUrl = `ws://${host}:${port}`;
    const wsWeb3 = new Web3(new Web3.providers.WebsocketProvider(wsUrl, { headers: { Origin: `http://${host}` } }));

    if (wsWeb3.eth.net.isListening()) {
      console.log('WebSocket network connected!');
    }

    if (type === 'logs') {
      var subscription = wsWeb3.eth.subscribe(type, { fromBlock: null }, (err, event) => { console.log(event); })
        .on('data', (log) => { console.log(log); });
    }
    if (type === 'pendingTransactions') {
      var subscription = wsWeb3.eth.subscribe(type, (err, event) => { console.log(event); })
        .on('data', (log) => { console.log(log); });
    }
    if (type === 'syncing') {
      var subscription = wsWeb3.eth.subscribe(type, (err, event) => { console.log(event); })
        .on('data', (log) => { console.log(log); });
    }

    subscription.unsubscribe((error, success) => {
      console.log(success);
      if (success) { console.log('Successfully unsubscribed!'); }
    });
  };


  // utils send transaciton function & Contract Process
  // 【test for check receipt info】
  async function UtilsContractDeploy(contract, from, password, privateKey) {
    const contract_info = fs.readFileSync(`../contract_detail_repo/${contract}_info.json`, 'utf8');
    const info = JSON.parse(contract_info);

    const txObject = {
      data: info.bytecode,
      gas: await web3.eth.estimateGas({ data: bytecode })
    };
    console.log('read to send');

    let signed;
    if (password !== '') signed = await web3.eth.personal.signTransaction(txObject, from, password);
    else if (privateKey !== '') signed = await web3.eth.accounts.signTransaction(txObject, privateKey);
    else return 'didn\'t insert account key or password';

    const txReceipt = await web3.eth.sendSignedTransaction(signed.rawTransaction);
    console.log(txReceipt);
    return { contract: txReceipt.contractAddress };
  }


  async function UtilsContractProcess(_from, contract, method, _parameters, _value, _privateKey, _password, execution, time) {
    const Contract = fs.readFileSync(`../contract_detail_repo/${contract}_info.json`, 'utf8');
    const ContractInfo = JSON.parse(Contract);
    const abi = JSON.parse(ContractInfo.abi);
    const { address } = ContractInfo;
    const { methodABI, decodeTypesArray } = methodProcess(method, abi);
    const data = web3.eth.abi.encodeFunctionCall(methodABI, parameters);

    if (execution === 'write') UtilsSendTx(_from, address, _value, data, _password, _privateKey);
    else if (execution === 'read') {
      const txObject = { to: address, data };
      const returnData = await web3.eth.call(txObject);
      const result = await web3.eth.abi.decodeParameters(decodeTypesArray, returnData);
      console.log(result);
      return result;
    } else {
      return new Error('send tx execution have some problem!');
    }


  }

  async function UtilsSendTx(from, to, value, data, password, privateKey) {
    let txObject = {
      to,
      value,
      data,
      gas: await web3.eth.estimateGas({ to, data }),
    };

    if (!privateKey) txObject.nonce = await web3.eth.getTransactionCount(from);
    console.log('ready to send');
    let signed;

    if (password !== '' && privateKey === '') {
      txObject.nonce = await web3.eth.getTransactionCount(from);
      txObject.from = from;
      signed = await web3.eth.personal.signTransaction(txObject, from, password);
    } else if (privateKey !== '' && password === '') {
      const address = await web3.eth.accounts.privateKeyToAccount(privateKey);
      txObject.nonce = await web3.eth.getTransactionCount(address);
      signed = await web3.eth.accounts.signTransaction(txObject, privateKey);
    } else {
      return new Error('send transaction have some problem');
    }

    web3.eth.sendSignedTransaction(signed.rawTransaction)
      .on('receipt', receipt => console.log(receipt))
      .on('error', err => new Error(err))
  }

  // 可以重複發送多個tx，只要設定loop 時間 和 結束時間即可
  function UtilsSendTxForLoop(to, value, data, privateKey, loopTime, endTime) {
    let acceptedTxCount = 0;
    let count = 0;
    let nonce = await web3.eth.getTransactionCount(_from);

    console.log('Loop process begin! ');
    const txAcceptCounter = setInterval(async () => {
      const txObject = {
        to,
        value,
        data,
        nonce: nonce + count,
        gas: await web3.eth.estimateGas({ to, data }),
      };
      count += 1;

      web3.eth.accounts.signTransaction(txObject, privateKey).then((result) => {
        web3.eth.sendSignedTransaction(result.rawTransaction)
          .on('receipt', () => acceptedTxCount += 1)
          .on('error', console.log);
      });
    }, loopTime * 1000);

    setTimeout(() => {
      console.log('num of contract transaction verified: ', acceptedTxCount);
      clearInterval(txAcceptCounter);
    }, endTime * 1000);
  }


  function methodProcess(method, abi) {
    const arr = [];
    const methodABI = {};
    const decodeTypesArray = [];

    for (const i in abi) {
      if (method == abi[i].name) {
        methodABI.name = method;
        methodABI.type = abi[i].type;
        for (var j in abi[i].inputs) {
          inputType = abi[i].inputs[j];
          arr.push(inputType);
        }
        for (var j in abi[i].outputs) {
          outputType = abi[i].outputs[j];
          decodeTypesArray.push(outputType);
        }
        methodABI.inputs = arr;
      }
    }
    return { methodABI, decodeTypesArray };
  };
}


module.exports = web3Operator;