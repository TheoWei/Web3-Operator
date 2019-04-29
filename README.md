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
    - [`privateKeyDeploy(contract, privateKey)`](#privatekeydeploycontract-privatekey)
    - [`accountDeploy(contract, from, password)`](#accountdeploycontract-from-password)
    - [`readContract(contract, method, parameters)`](#readcontractcontract-method-parameters)
    - [`accountWriteContract(from, contract, method, parameters, value, password)`](#accountwritecontractfrom-contract-method-parameters-value-password)
    - [`privateKeylWriteContract(contract, method, parameters, value, privateKey)`](#privatekeylwritecontractcontract-method-parameters-value-privatekey)
    - [`ListeningEvent(type, host, port)`](#listeningeventtype-host-port)

## Usage
```javascript
const Web3operator = require('web3-operator');
const web3operator = new Web3operator(web3_rpc);
```

## Account_operation
### `createAccount(random)`
create account by random number 
* `random` is a string
```javascript
web3operator.createAccount(random)
// > 
```

### `queryAccount(privateKey)`
query account by private key 
* `privateKey` is a string
```javascript
web3Operator.queryAccount(privateKey)
// >  
```
### `decryptAccount(keyStoreJson, password)`
decrypt account by account keyStoreJson and account password
* `keyStoreJson`
* `password` is a string
```javascript
web3Operator.decryptAccount(keyStoreJson, password)
// >  
```

### `encryptAccount(privateKey, password)`
encrypt account by account keyStoreJson and account password
* `privateKey` is a string
* `password` is a string
```javascript
web3Operator.encryptAccount(privateKey, password)
// >  
```

### `importKey(privateKey, password)`
import private key to node , that will convert to keyStoreJson
* `privateKey` is a string
* `password` is a string
```javascript
web3Operator.importKey(privateKey, password)
// >  
```

## Contract_interaction

### `compiles(contract)`
compile contract from ./contract directory        
* `contract` is a string
```javascript
web3Operator.compiles(contract)
// >  
```

### `privateKeyDeploy(contract, privateKey)`
use private key to deploy contract
* `contract` is a string
* `privateKey` is a string
```javascript
web3Operator.privateKeyDeploy(contract, privateKey)
// >  
```

### `accountDeploy(contract, from, password)`
use account address and password to deploy contract
* `contract` is a string
* `from` is a string
* `password` is a string
  
```javascript
web3Operator.accountDeploy(contract, from, password)
// >  
```

### `readContract(contract, method, parameters)`
read indicate contract method
* `contract` is a string
* `method` is a string
* `parameters` is a string

```javascript
web3Operator.readContract(contract, method, parameters)
// >  
```

### `accountWriteContract(from, contract, method, parameters, value, password)`
use account address and password to write contract
* `from` is a string
* `contract` is a string
* `method` is a string
* `parameters` is a string
* `value` is a string
* `password` is a string
  
```javascript
web3Operator.accountWriteContract(from, contract, method, parameters, value, password)
// >  
```

### `privateKeylWriteContract(contract, method, parameters, value, privateKey)`
use private key to write contract
* `contract` is a string
* `method` is a string
* `parameters` is a string
* `value` is a string
* `privateKey` is a string

```javascript
web3Operator.privateKeylWriteContract(contract, method, parameters, value, privateKey)
// >  
```

### `ListeningEvent(type, host, port)`
listening specific event 
* `type` is a string
* `host` is a string
* `port` is a string

```javascript
web3Operator.ListeningEvent(type, host, port)
// >  
```

