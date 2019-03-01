# Web3 Operator
## Functionality 
1. create account
2. privatekey to account address
3. compile contract
4. deploy contract
5. read contract
6. write contract
7. listen event

## create private node
- download [go-ethereum]()
- create genesis.json
```json
{
  "config": {
        "chainId": 0, 
        "homesteadBlock": 0,
        "eip155Block": 0,
        "eip158Block": 0
    },
  "alloc"      : {},
  "coinbase"   : "0x0000000000000000000000000000000000000000",
  "difficulty" : "0x20000",
  "extraData"  : "",
  "gasLimit"   : "0x2fefd8",
  "nonce"      : "0x0000000000000042",
  "mixhash"    : "0x0000000000000000000000000000000000000000000000000000000000000000",
  "parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp"  : "0x00"
}
```
- start command
    * initialize
        `$ geth --datadir [/path/directory/node1] init `
    * start up Geth Javascript console
        `$ geth --datadir [/path/directory/node1] --rpc --rpcport "" --rpcapi []' --port [port] --networkid [id] --discover console`
>  now you can command web3 method or geth management api 

## connect with other node
- these following condition are key point if you want connect with other node 
    * use same genesis.json
    * command same networkid

- initialize and start up geth in another server
`$ geth --datadir [/path/directory/node2] init `
`$ geth --datadir [/path/directory/node2] --rpc --rpcport "" --rpcapi []' --port [port] --networkid [use same id] --discover console`

- now we have 2 node in different server
- check node1 information
`> admin.nodeInfo.enode()`

- copy respond string
`> "enode:...@[::]:port"`

- go to another server (or vm in your pc) and start up geth 
`$ geth --datadir [/path/directory/node2] --rpc --rpcport "" --rpcapi []' --port [port] --networkid [use same id] --discover console`

- ready to connect another node use node1 enode string
    `> admin.addPeer("enode:...@node1_ip:port")`
- check connections status
    `> admin.peers()`
- node been connected now 

