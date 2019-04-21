module.exports = function core(rpcUrl) {
  const fs = require('fs');
  const Web3 = require('web3');
  const solc = require('solc');

  const web3 = new Web3(rpcUrl);
  if (web3.eth.net.isListening()) console.log('network connected!');

  // account operation
  this.createAccount = function (random) {
    const accountObject = web3.eth.accounts.create(random);
    console.log('Here\'s account object::  ', accountObject);
    return accountObject;
  };
  this.queryAccount = (privateKey) => {
    const account = web3.eth.accounts.privateKeyToAccount(privateKey);
    console.log('Your account address::  ', account.address);
    return account.address;
  };
  this.decryptAccount = async (keyStoreJson, password) => {
    const decrypted = await web3.eth.accounts.decrypt(keyStoreJson, password);
    console.log('decrpyt one of accounts from node:: ', decrypted);
    return decrypted;
  };
  this.encryptAccount = async (privateKey, password) => {
    const keyStoreJson = await web3.eth.accounts.encrypt(privateKey, password);
    console.log('Here\'s your keyStoreJson::', keyStoreJson);
    return keyStoreJson;
  };
  this.importKey = async (privateKey, password) => {
    const address = await web3.eth.personal.importRawKey(privateKey, password);
    console.log('This is your account address:: ', address);
    return true;
  };


  // general function
  this.test = async function (value) {
    return console.log(web3.utils.asciiToHex(value));
  };

  this.Crypto = (data, exec) => {
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
  this.hash = function (data) {
    data = JSON.stringify(data);
    const hash_data = web3.utils.sha3(data);
    return hash_data;
  };


  // contract interaction
  this.compiles = function (contract) {
    // load file > compile > get abi & bytecode
    console.log('read file...');
    const file = fs.readFileSync(`/contract/${contract}.sol`, 'utf8');
    console.log('compile....');

    const compiledContract = solc.compile(file);
    console.log('done');
    console.log(compiledContract);
    const bytecode = `0x${compiledContract.contracts[`:${contract}`].bytecode}`;
    const abi = compiledContract.contracts[`:${contract}`].interface;

    const output = { contract, abi, bytecode };
    fs.writeFile(`../contract_detail_repo/${contract}_info.json`, JSON.stringify(output), (err, file) => {
      !err ? console.log('writed abi! ') : console.log(err);
    });
    return true;
  };

  this.privateKeyToDeploy = function (contract, privateKey) {
    UtilsContractDeploy(contract, '', '', privateKey);
  };
  this.accountToDeploy = function (contract, from, password) {
    UtilsContractDeploy(contract, from, password, '');
  };

  this.readContract = function (contract, method, parameters) {
    return UtilsContractProcess(contract, method, parameters, 0, '', '', 'read', false, 0);
  };

  this.accountToWriteContract = function (from, contract, method, parameters, value, password) {
    UtilsContractProcess(from, contract, method, parameters, value, '', password, 'write', false, 0);
  };
  this.privateKeyToWriteContract = function (contract, method, parameters, value, privateKey) {
    UtilsContractProcess('', contract, method, parameters, value, privateKey, '', 'write', false, 0);
  };

  this.ListeningEvent = function (type, host, port) {
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
  async function UtilsContractDeploy(_contract, _from, _password, _privateKey) {
    const contract_info = fs.readFileSync(`../contract_detail_repo/${_contract}_info.json`, 'utf8');
    const info = JSON.parse(contract_info);

    const txObject = { 
      data: info.bytecode, 
      gas: await web3.eth.estimateGas({ data: bytecode }) 
    };
    console.log('read to send');

    let signed;
    if (_password !== '') signed = await web3.eth.personal.signTransaction(txObject, _from, _password);
    else if (_privateKey !== '') signed = await web3.eth.accounts.signTransaction(txObject, _privateKey);
    else return 'didn\'t insert account key or password';

    const txReceipt = await web3.etj.sendSignedTransaction(signed.rawTransaction);

    info.address = txReceipt.contractAddress;
    fs.writeFileSync(`../contract_detail_repo/${contract}_info.json`, JSON.stringify(info), 'utf8');
  }

  async function UtilsContractProcess(_from, _contract, _method, _parameters, _value, _privateKey, _password, execution, test, time) {
    const contract_info = fs.readFileSync(`../contract_detail_repo/${_contract}_info.json`, 'utf8');
    const info = JSON.parse(contract_info);

    const abi = JSON.parse(info.abi);
    const _address = info.address;

    const methodABI = methodProcess(abi);

    const _data = web3.eth.abi.encodeFunctionCall(methodABI, parameters);
    if (execution == 'write') {
      if (!test) UtilsSendTx(_from, _address, _value, _data, _password, _privateKey);
      else UtilsSendTxForTest(address, value, data, privateKey, time);
    } else if (execution == 'read') {
      const txobject = {
        to: _address,
        data,
      };
      const returnData = await web3.eth.call(txobject);
      const result = await web3.eth.abi.decodeParameters(decodeTypesArray, returnData);
      console.log(result);
      return result;
    } else {

    }
  }

  async function UtilsSendTx(_from, _to, _value, _data, _password, _privateKey) {
    const txObject = {
      to: _to,
      value: _value,
      data: _data,
      gas: await web3.eth.estimateGas({ to: _to, data: _data }),
    };
    if (!_privateKey) txObject.nonce = await web3.eth.getTransactionCount(_from);

    console.log('ready to send');

    let signed;
    if (_password !== '') {
      txObject.nonce = await web3.eth.getTransactionCount(_from);
      txObject.from = _from;
      signed = await web3.eth.personal.signTransaction(txObject, _from, _password);
    } else if (_privateKey !== '') {
      const address = await web3.eth.accounts.privateKeyToAccount(_privateKey);
      txObject.nonce = await web3.eth.getTransactionCount(address);
      signed = await web3.eth.accounts.signTransaction(txObject, _privateKey);
    }

    web3.eth.sendSignedTransaction(signed.rawTransaction)
      .on('receipt', (receipt) => {
        console.log(receipt);
      })
      .on('error', console.log);
  }

  function UtilsSendTxForTest(_to, _value, _data, privateKey, time) {
    const interval = time * 1000;
    let acceptedTxCount = 0;

    console.log('Test process begin! ');
    const txAcceptCounter = setInterval(async () => {
      const txObject = {
        to: _to,
        value: _value,
        data: _data,
        gas: await web3.eth.estimateGas({ to: _to, data: _data }),
      };

      web3.eth.accounts.signTransaction(txObject, privateKey).then((result) => {
        web3.eth.sendSignedTransaction(result.rawTransaction)
          .on('receipt', (receipt) => {
            acceptedTxCount++;
          })
          .on('error', console.log);
      });
    }, interval);

    setTimeout(() => {
      console.log('num of contract transaction verified in 1 min: ', acceptedTxCount);
      clearInterval(txAcceptCounter);
    }, 60000);
  }


  function methodProcess(abi){
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
    return methodABI;
  }
};
