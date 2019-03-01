
module.exports = function core(rpcUrl) {
    const fs = require('fs');
    const Web3 = require('web3');
    const solc = require('solc');

    const web3 = new Web3(rpcUrl);
    if (web3.eth.net.isListening()) console.log('network connected!');

    // account operation 
    this.createAccount = function (random) {
        let accountObject = web3.eth.accounts.create(random);
        console.log(accountObject);
        return accountObject;
    }
    this.queryAccount = (prikey)=>{
        let account = web3.eth.accounts.privateKeyToAccount(prikey);
        console.log(account.address);
        return account.address;
    }


    // general function 
    this.test = async function (value) {
        return console.log(web3.utils.asciiToHex(value));
    }

    this.Crypto = (data, exec) => {

        const crypto = require('crypto'),
            algorithm = 'aes-256-cbc',
            key = crypto.randomBytes(32),
            iv = crypto.randomBytes(16);

        

        if (exec == 'encrypt') {
            data = JSON.stringify(data);
            console.log('start encrypt');
            let enc_data = encrypt(data);
            return enc_data;
        } else if (exec == 'decrypt') {
            console.log('start decrypt');
            let dec_data = decrypt(data);
            return dec_data;
        } else {
            return console.error('error');
        }

        function encrypt(data) {
            let cipher = crypto.createCipheriv(algorithm, key, iv);
            let encrypted = cipher.update(data);
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            return {key: key.toString('hex'), iv: iv.toString('hex'), encryptedData: encrypted.toString('hex')};
        }
        function decrypt(data) {
            let _iv = Buffer.from(data.iv,'hex');
            let _key = Buffer.from(data.key,'hex');
            let _encryptedData = Buffer.from(data.encryptedData,'hex');
            let decipher = crypto.createDecipheriv(algorithm, _key, _iv);
            let decrypted = decipher.update(_encryptedData);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            return decrypted.toString();
        }
    }
    this.hash = function (data) {
        data = JSON.stringify(data);
        let hash_data = web3.utils.sha3(data)
        return hash_data;
    }


    //contract interaction 
    this.compiles = function (_contractName) {

        //load file > compile > get abi & bytecode
        console.log('read file...');
        var file = fs.readFileSync(`/contract/${_contractName}.sol`, 'utf8');
        console.log('compile....');

        var compiledContract = solc.compile(file);
        console.log('done');
        console.log(compiledContract);
        var bytecode = '0x' + compiledContract.contracts[`:${_contractName}`].bytecode;
        var abi = compiledContract.contracts[`:${_contractName}`].interface;


        fs.writeFile(`/contract_detail/${_contractName}_abi.json`, abi, function (err, file) {
            if (!err) {
                console.log('writed abi! ');

            } else {
                throw err;
            }
        });

        fs.writeFile(`/contract_detail/${_contractName}_bytecode.json`, bytecode, function (err, file) {
            if (!err) {
                console.log('writed bytecode! ');

            } else {
                throw err;
            }
        });

        return;
    }


    this.deploy = function (param, sender, _password, _contractName) {
        let abi = fs.readFileSync(`/contract_detail/${_contractName}_abi.json`, 'utf8');
        let abiArr = JSON.parse(abi);
        let bytecode = fs.readFileSync(`/contract_detail/${_contractName}_bytecode.json`, 'utf8');

        var gasEstimate;
        //create contract instance to deploy
        let MyContract = new web3.eth.Contract(abiArr, { data: bytecode });

        //first deploy is for estimate gas
        web3.eth.personal.unlockAccount(sender, _password)
            .then(() => {
                MyContract.deploy().estimateGas(function (err, gas) {
                    console.log(gas);
                    gasEstimate = gas;
                }).then(() => {
                    //second deploy is for trully deploy contract
                    let myContractInstance = MyContract.deploy().send({
                        from: sender,
                        gasPrice: 1,
                        gas: gasEstimate
                    }, function (err, txHash) {
                        console.log(`transaction hash ::  ${txHash}`);
                    }).then(contractInstance => {
                        console.log(`contract address ::  ${contractInstance.options.address}`);
                        fs.writeFileSync(`/contract_detail/${_contractName}_address.js`, contractInstance.options.address);
                    });

                });

            });

    }


    this.readSC = function (_contract,method,parameter_Array) {
        return UtilsContractProcess(0, '', _contract, method, parameter_Array, 'read', false, 0);
    }

    this.writeSC = function (value, privateKey, _contract, method, parameter_Array) {
        UtilsContractProcess(value, privateKey, _contract, method, parameter_Array, 'write', false, 0);
    }

    this.ListeningEvent = function (type,host, port) {
        var wsUrl = `ws://${host}:${port}`;
        var wsWeb3 = new Web3(new Web3.providers.WebsocketProvider(wsUrl, { headers: { Origin: `http://${host}` } }));

        if (wsWeb3.eth.net.isListening()) {
            console.log('WebSocket network connected!');
        }

        if(type === 'logs') {
            var subscription = wsWeb3.eth.subscribe(type, { fromBlock: null }, function (err, event) { console.log(event); })
            .on('data',function (log) { console.log(log); });
        }
        if(type === 'syncing') {
            var subscription = wsWeb3.eth.subscribe(type, function (err, event) { console.log(event); })
            .on('data',function (log) { console.log(log);});
        }
        
        subscription.unsubscribe(function (error, success) {
            console.log(success);
            if (success)
                console.log('Successfully unsubscribed!');
        });
    }
    

    // utils send transaciton function & Contract Process 
    async function UtilsContractProcess(value, privateKey, _contract, method, parameter_Array, execution, test, time) {
        let abi = fs.readFileSync(`/contract_detail/${_contract}_abi.json`, 'utf8');
        var abiArr = JSON.parse(abi);
        let contractAddress = fs.readFileSync(`/contract_detail/${_contract}_address.js`, 'utf8');
        var contractInstance = new web3.eth.Contract(abiArr, contractAddress); //如果是接上 sendSignedTx fucntion，contract address 並不用再contract instance 那邊建立

        let arr = [];
        let methodABI = {};
        let decodeTypesArray = [];
        for (var i in abiArr) {
            if (method == abiArr[i].name) {
                methodABI.name = method;
                methodABI.type = abiArr[i].type;
                for (var j in abiArr[i].inputs) {
                    inputType = abiArr[i].inputs[j];
                    arr.push(inputType);
                }
                for(var j in abiArr[i].outputs){
                    outputType = abiArr[i].outputs[j];
                    decodeTypesArray.push(outputType);
                }
                methodABI.inputs = arr;
            }
        }
        
        let data = web3.eth.abi.encodeFunctionCall(methodABI, parameter_Array);
        if(execution == 'write') {
            if (!test) UtilsSendTx(contractAddress, value, data, privateKey);
            else UtilsSendTxForTest(contractAddress, value, data, privateKey, time);
        }else if(execution == 'read'){
            var txobject = {
                to: contractAddress,
                data: data
            };    
            let returnData = await web3.eth.call(txobject);
            let result = await web3.eth.abi.decodeParameters(decodeTypesArray,returnData);
            return result;
        }else{
            return ;
        }


    }

    async function UtilsSendTx(_to, _value, _data, privateKey) {
        let txObject = {
            to: _to,
            value: _value,
            data: _data,
            gas: await web3.eth.estimateGas({to:_to,data:_data})
        }

        console.log('ready to send');
        web3.eth.accounts.signTransaction(txObject, privateKey).then((result) => {
            web3.eth.sendSignedTransaction(result.rawTransaction)
                .on('receipt', (receipt) => {
                    console.log(receipt);
                })
                .on('error', console.log);
        })
    }

    function UtilsSendTxForTest(_to, _value, _data, privateKey, time) {

        let interval = time * 1000;
        let acceptedTxCount = 0;

        console.log('Test process begin! ');
        let txAcceptCounter = setInterval(async () => {
            let txObject = {
                to: _to,
                value: _value,
                data: _data,
                gas: await web3.eth.estimateGas({to:_to,data:_data})
            }

            web3.eth.accounts.signTransaction(txObject, privateKey).then((result) => {
                web3.eth.sendSignedTransaction(result.rawTransaction)
                    .on('receipt', (receipt) => {
                        acceptedTxCount++;
                    })
                    .on('error', console.log);
            })
        }, interval);

        setTimeout(() => {
            console.log('num of contract transaction verified in 1 min: ', acceptedTxCount);
            clearInterval(txAcceptCounter);
            return;
        }, 60000)
    }

}



