const fs = require('fs');
const Web3 = require('web3');
const solc = require('solc');

function web3Operator(rpcUrl) {
  const web3 = new Web3(rpcUrl);
  if (web3.eth.net.isListening()) console.log('ethereum node connected!');

  // account operation 
  this.createAccount = (random) => {
    let accountObject = web3.eth.accounts.create(random);
    return accountObject;
  }
  this.queryAccount = (prikey) => {
    let account = web3.eth.accounts.privateKeyToAccount(prikey);
    return account.address;
  }
  this.decryptAccount = async (keyStoreJson, password) => {
    let decrypted = await web3.eth.accounts.decrypt(keyStoreJson, password);
    return decrypted;
  }
  this.importKey = async (privateKey, password) => {
    await web3.eth.personal.importRawKey(privateKey, password);
    return true;
  }
  this.encryptAccount = async (privateKey, password) => {
    let keyStoreJson = await web3.eth.accounts.encrypt(privateKey, password);
    return keyStoreJson;
  }
  this.sha3_hash = (data) => {
    let hash_data = web3.utils.sha3(JSON.stringify(data))
    return hash_data;
  }


  // general function
  this.sha3Hash = (data) => {
    data = JSON.stringify(data);
    const hash_data = web3.utils.sha3(data);
    return hash_data;
  };


  // contract interaction
  this.compiles = (contract) => {
    // load file > compile > get abi & bytecode
    console.log('read file...');
    const file = fs.readFileSync(`/contract/${contract}.sol`, 'utf8');
    console.log('compile....');

    const compiledContract = solc.compile(file);
    console.log('done');

    const bytecode = '0x' + compiledContract.contracts[`:${_contract}`].bytecode;
    const abi = compiledContract.contracts[`:${_contract}`].interface;

    return { contract, abi, bytecode };
  };

  this.privateKeyToDeploy = (bytecode, privateKey) => {
    return UtilsContractDeploy(bytecode, '', '', privateKey);
  };
  this.accountToDeploy = (bytecode, from, password) => {
    return UtilsContractDeploy(bytecode, from, password, '');
  };

  this.readContract = (contractAddress, abi, method, parameters) => {
    return UtilsContractProcess('', contractAddress, abi, method, parameters, 0, '', '', 'read');
  };

  this.accountToSendEther = (from, to, value, password) => {
    return UtilsSendTx(from, to, value, '', password, '');
  };
  this.privateKeyToSendEther = (from, to, value, privateKey) => {
    return UtilsSendTx(from, to, value, '', '', privateKey);
  };

  this.accountToWriteContract = (from, contractAddress, abi, method, parameters, value, password) => {
    return UtilsContractProcess(from, contractAddress, abi, method, parameters, value, '', password, 'write');
  };
  this.privateKeyToWriteContract = (contractAddress, abi, method, parameters, value, privateKey) => {
    return UtilsContractProcess('', contractAddress, abi, method, parameters, value, privateKey, '', 'write');
  };

  this.accountToLoopWriteContract = (from, contractAddress, abi, method, parameters, value, password, loopTime, endTime) => {
    return UtilsContractProcess(from, contractAddress, abi, method, parameters, value, '', password, 'loopWrite', loopTime, endTime);
  };
  this.privateKeyToLoopWriteContract = (contractAddress, method, parameters, value, privateKey, loopTime, endTime) => {
    return UtilsContractProcess('', contractAddress, abi, method, parameters, value, privateKey, '', 'loopWrite', loopTime, endTime);
  };

  this.ListeningEvent = (type, host, port) => {
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
  this.UtilsContractDeploy = async (bytecode, from, password, privateKey) => {
    const txObject = {
      data: bytecode,
      gas: await web3.eth.estimateGas({ data: bytecode })
    };
    console.log('read to send');

    let signed;
    if (password !== '' && privateKey === '') signed = await web3.eth.personal.signTransaction(txObject, from, password);
    else if (privateKey !== '' && password === '') signed = await web3.eth.accounts.signTransaction(txObject, privateKey);
    else return new Error('didn\'t insert account key or password');

    return web3.eth.sendSignedTransaction(signed.rawTransaction)
      .on('receipt', receipt => { return receipt });
  }


  this.UtilsContractProcess = async (from, to, abi, method, parameters, value, privateKey, password, execution, loopTime = 0, endTime = 0) => {
    const { methodABI, decodeTypesArray } = methodProcess(method, abi);
    const data = web3.eth.abi.encodeFunctionCall(methodABI, parameters);
    console.log('pass contract process!');

    if (execution === 'write') return UtilsSendTx(from, to, value, data, password, privateKey);
    else if (execution === 'read') {
      const txObject = { to, data };
      const returnData = await web3.eth.call(txObject);
      const result = await web3.eth.abi.decodeParameters(decodeTypesArray, returnData);
      return result;
    }
    else if (execution === 'loopWrite') {
      if (password !== '' && privateKey === '') return UtilsLoopSendTxByPassword(from, to, value, data, password, loopTime, endTime);
      else if (privateKey !== '' && password === '') return UtilsLoopSendTxByPrivatekey(to, value, data, privateKey, loopTime, endTime);
      else return new Error('loop write process failed!');
    }
    else return new Error('send tx execution have some problem!');
  }

  this.UtilsSendTx = async (from, to, value, data, password, privateKey) => {
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
      return new Error('send transaction failed!');
    }

    return web3.eth.sendSignedTransaction(signed.rawTransaction)
      .on('receipt', receipt => { return receipt })
      .on('error', err => new Error(err))
  }

  // 可以重複發送多個tx，只要設定loop 時間 和 結束時間即可
  this.UtilsLoopSendTxByPassword = async (from, to, value, data, password, loopTime, endTime) => {
    let acceptedTxCount = 0;
    let count = 0;
    let nonce = await web3.eth.getTransactionCount(from);

    console.log('Loop process begin! ');
    const txAcceptCounter = setInterval(async () => {
      const txObject = {
        from,
        to,
        value,
        data,
        nonce: nonce + count,
        gas: await web3.eth.estimateGas({ to, data }),
      };
      count += 1;

      web3.eth.accounts.signTransaction(txObject, from, password).then((result) => {
        web3.eth.sendSignedTransaction(result.rawTransaction)
          .on('receipt', () => acceptedTxCount += 1)
          .on('error', console.log);
      });
    }, loopTime * 1000);

    setTimeout(() => {
      console.log('num of contract transaction verified: ', acceptedTxCount);
      clearInterval(txAcceptCounter);
      return true;
    }, endTime * 1000);
  }

  this.UtilsLoopSendTxByPrivatekey = async (to, value, data, privateKey, loopTime, endTime) => {
    const address = await web3.eth.accounts.privateKeyToAccount(privateKey);
    let acceptedTxCount = 0;
    let count = 0;
    let nonce = await web3.eth.getTransactionCount(address);

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
      return true;
    }, endTime * 1000);
  }

  this.methodProcess = (method, abi) => {
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