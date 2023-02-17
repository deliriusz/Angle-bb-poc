# Angle Protocol bug bounty findings

## Description
This repo contains PoCs for 2 issues I found while bounty hunting Angle Protocol on Immunefi.
* lib - forge related libs, all bundled for convenience
* src - source code for the `Router` contract and its dependencies
* test - actual PoCs I used when proving the issues to the Angle team

You can find full writeup on [Medium](https://medium.com/@deliriusz/stealing-in-motion-immunefi-bounty-hunting-from-different-angle-5eb03602f5c1).

## PoC description
`StorageSlot.sol` is just a helper I used to be able to override any storage slot

`POC-reentrancy-erc777.t.sol` contains test for the first submission - stealing from other users via reentrancy. Two cases are consider - in the minimum amount of token to sweep is set to zero, and if it is set to some slippage

`POC-vault.t.sol` contains test for second submission - stealing other users' vaults via reentrancy. This is a fun one :-)

## Setup
```
foundryup
forge test
```