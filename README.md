# Web3 Operator
> Web3 opertor is combined with web3 library for easily to interact with Ethereum

- [Web3 Operator](#web3-operator)
  - [Usage](#usage)
  - [Account_operation](#accountoperation)
    - [`createAccount(random)`](#createaccountrandom)
    - [`queryAccount(privateKey)`](#queryaccountprivatekey)
    - [`decryptAccount(keyStoreJson, password)`](#decryptaccountkeystorejson-password)
    - [`encryptAccount(privateKey, password)`](#encryptaccountprivatekey-password)
    - [`importKey(privateKey, password)`](#importkeyprivatekey-password)
  - [Contract_interaction](#contractinteraction)
    - [`compiles(contract)`](#compilescontract)
    - [`privateKeyDeploy(bytecode, privateKey)`](#privatekeydeploybytecode-privatekey)
    - [`accountDeploy(bytecode, from, password)`](#accountdeploybytecode-from-password)
    - [`readContract(contractAddress, abi, method, parameters)`](#readcontractcontractaddress-abi-method-parameters)
    - [`accountWriteContract(from, contractAddress, abi, method, parameters, value, password)`](#accountwritecontractfrom-contractaddress-abi-method-parameters-value-password)
    - [`privateKeylWriteContract(contractAddress, abi, method, parameters, value, privateKey)`](#privatekeylwritecontractcontractaddress-abi-method-parameters-value-privatekey)
    - [`accountToLoopWriteContract(from, contractAddress, abi, method, parameters, value, password, loopTime, endTime)`](#accounttoloopwritecontractfrom-contractaddress-abi-method-parameters-value-password-looptime-endtime)
    - [`privateKeyToLoopWriteContract(contractAddress, abi, method, parameters, value, privateKey, loopTime, endTime)`](#privatekeytoloopwritecontractcontractaddress-abi-method-parameters-value-privatekey-looptime-endtime)
    - [`ListeningEvent(type, host, port)`](#listeningeventtype-host-port)

## Usage
1. Create contract store directory
```
$ mkdir contract
```
2. import module 
```javascript
const Web3operator = require('web3-operator');
const web3operator = new Web3operator(web3_rpc);
```

## Account_operation
### `createAccount(random)`
create account by random number 
* `random` - `String`: random string 
```javascript
web3operator.createAccount(random)
/* 
> return {
    address: ...,
    privateKey: ...,
    signTransaction: function(tx){...},
    sign: function(data){...},
    encrypt: function(password){...}
  }
*/
```

### `queryAccount(privateKey)`
query account by private key 
* `privateKey` - `String`: private key
```javascript
web3Operator.queryAccount(privateKey)
/* 
> return {
    address: ...,
    privateKey: ...,
    signTransaction: function(tx){...},
    sign: function(data){...},
    encrypt: function(password){...}
  }
*/
```
### `decryptAccount(keyStoreJson, password)`
decrypt account by account keyStoreJson and account password
* `keyStoreJson` - `Object` if your account created in local node, it should store in ./node/keyStore
* `password` - `String`: sender account password
```javascript
web3Operator.decryptAccount(keyStoreJson, password)
/* 
> return {
    address: ...,
    privateKey: ...,
    signTransaction: function(tx){...},
    sign: function(data){...},
    encrypt: function(password){...}
  }
*/
```

### `encryptAccount(privateKey, password)`
encrypt account by account keyStoreJson and account password
* `privateKey` - `String`: private key
* `password` - `String`: sender account password
```javascript
web3Operator.encryptAccount(privateKey, password)
// >  return keyStoreJson

```

### `importKey(privateKey, password)`
import private key to node , that will convert to keyStoreJson
* `privateKey` - `String`: private key
* `password` - `String`: sender account password
```javascript
web3Operator.importKey(privateKey, password)
// >  
```

## Contract_interaction

### `compiles(contract)`
compile contract from `./contract` directory        
* `contract` - `String`: contract name
```javascript
web3Operator.compiles(contract)
// >  return abi and bytecode
```

### `privateKeyDeploy(bytecode, privateKey)`
use private key to deploy contract
* `bytecode` - `String`: contract bytecode
* `privateKey` - `String`: private key
```javascript
web3Operator.privateKeyDeploy(bytecode, privateKey)
// >  return transaction receipt , recommand to find contractAddress of attribute for contract interaction 
```

### `accountDeploy(bytecode, from, password)`
use account address and password to deploy contract
* `bytecode` - `String`: contract bytecode
* `from` - `Address`: sender account address
* `password` - `String`: sender account password
  
```javascript
web3Operator.accountDeploy(bytecode, from, password)
// >  return transaction receipt , recommand to find contractAddress of attribute for contract interaction 
```

### `readContract(contractAddress, abi, method, parameters)`
read indicate contract method
* `contractAddress` - `String`: contract address
* `abi` - `Array`: contract abi
* `method` - `String`: contract function name
* `parameters` - `Array`: contract function parameters 

```javascript
web3Operator.readContract(contractAddress, abi, method, parameters)
// >  return contract data
```

### `accountWriteContract(from, contractAddress, abi, method, parameters, value, password)`
use account address and password to write contract
* `from` - `Address`: sender account address, mean 
* `contractAddress` - `String`: contract name
* `abi` - `Array`: contract abi
* `method` - `String`: contract function name
* `parameters` - `Array`: contract function parameters 
* `value` - `Number`: ether value
* `password` - `String`: sender account password
  
```javascript
web3Operator.accountWriteContract(from, contractAddress, abi, method, parameters, value, password)
// >  return transaction receipt
```

### `privateKeylWriteContract(contractAddress, abi, method, parameters, value, privateKey)`
use private key to write contract
* `contractAddress` - `String`: contract name
* `abi` - `Array`: contract abi
* `method` - `String`: contract function name
* `parameters` - `Array`: contract function parameters 
* `value` - `Number`: ether value
* `privateKey` - `String`: private key

```javascript
web3Operator.privateKeylWriteContract(contractAddress, abi, method, parameters, value, privateKey)
// >  return transaction receipt
```

### `accountToLoopWriteContract(from, contractAddress, abi, method, parameters, value, password, loopTime, endTime)`
use private key to write contract for loop before  endTime, after respond the amount of confirmed transaction

* `from` - `Address`: sender account address, mean 
* `contractAddress` - `String`: contract name
* `abi` - `Array`: contract abi
* `method` - `String`: contract function name
* `parameters` - `Array`: contract function parameters 
* `value` - `Number`: ether value
* `password` - `String`: sender account password
* `loopTime` - `Number`: send transaction in loop 
* `endTime` - `Number`: the time for finish loop send transaction process 
  
```javascript
web3Operator.accountToLoopWriteContract(from, contractAddress, abi, method, parameters, value, password, loopTime, endTime)
// >  return true
```

### `privateKeyToLoopWriteContract(contractAddress, abi, method, parameters, value, privateKey, loopTime, endTime)`
use private key to write contract for loop before  endTime, after respond the amount of confirmed transaction

* `contractAddress` - `String`: contract name
* `abi` - `Array`: contract abi
* `method` - `String`: contract function name
* `parameters` - `Array`: contract function parameters 
* `value` - `Number`: ether value
* `privateKey` - `String`: private key
* `loopTime` - `Number`: send transaction in loop
* `endTime` - `Number`: the time for finish loop send transaction process 
  
```javascript
web3Operator.privateKeyToLoopWriteContract(contractAddress, abi, method, parameters, value, privateKey, loopTime, endTime)
// >  return true
```

### `ListeningEvent(type, host, port)`
listening specific event 
* `type` - `String` can be `logs`、`pendingTransactions`、`syncing`
* `host` - `String` websocket host
* `port` - `String` websocket port

```javascript
web3Operator.ListeningEvent(type, host, port)
// >  listening 
```

