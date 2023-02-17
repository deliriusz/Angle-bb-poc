# Report 1
## Title
Direct theft of any user funds using `AngleRouter::mixer`

## Description
There is an issue with AngleRouter accross multiple chains: Arbitrum, Avalanche, Eth Mainnet, Optimism and Polygon, allowing malicious users to steal from others using `BaseRouter::mixer`
Because `BaseRouter::mixer` does not have reentrancy check, every function that uses ERC20 transfers, e.g. Router::_sweep, Router::_transfer, Router::*4626, etc. - may allow reentrancy if using erc777 - malicious actor may reenter the smart contract and drain user funds up to allowed slippage. If slippage is not set (as in this transaction: https://polygonscan.com/tx/0x561c3ef6de1ab6c5b6166763fdaa4ef9ebc6711ea07fcdac04b774e334f45586 where last operation is sweep with minAmountOut = 0), then malicious user may steal all the funds.
BaseReactor::_deposit - states in documentation "Need to transfer before minting or ERC777s could reenter" - it's ERC4626 implementation, which suggests that there will be support for ERC777s. I observed many interactions with ERC4626 vaults on L2s, which may be specifically impacted.
And operations like Router::swapper, Router::oneInch and Router::uniswapV3 functions, which allow swapping any arbitrary token A for a token B, thus allowing for reentrancy if ERC777 is used.
Additionally, while not probable, `VaultManager::angle` allows for reentrancy to `AngleRouter::mixer` via `createVault` operation, and more specifically `onERC721Received` hook

Additionally, I see that there are 12$ in USDC and 12$ in FRAX residing at the moment in the AngleRouterMainnet: https://etherscan.io/address/0x4579709627CA36BCe92f51ac975746f431890930
According to the natspec:
> the protocol
> does not verify the payload given and cannot check that the swap performed by users actually gives the desired
> out token: in this case funds may be made accessible to anyone on this contract if the concerned users
> do not perform a sweep action on these tokens

Only 3 transactions took place at the moment of writing this report, and already there is 24$ in the smart contract that was not swept for anyone to take, which indicates that there might be some problem with a frontend putting the operations together, not doing its job not adding `sweep` at the end correctly.

## Attack flow
0. Malicious actor creates a malicious contract that reenters the AngleRouter and steals user funds
1. Malicious actor listens for a specific transaction in the mempool and checks the slippage - frontruns the execution to set percentage to steal accordingly
2. Victim creates following transaction for mixer function:
- transfer: transfer collateral together with a token susceptible to arbitrary call (e.g. ERC777)
- swap: swap tokens for other susceptible ones
- transfer: transfer to a malicious user
- sweep: sweep tokens checking slippage
3. When transfer to a malicious contract takes place, it reenters the `AngleRouter::mixer`, sweeps all the funds and returns those up to a slippage amount

## Risk Breakdown
Difficulty to Exploit: Medium
Weakness: funds stealing

## Recommended fix
1. Add reentracny check in BaseRouter::mixer
2. Consider sweeping the smart contract to `msg.sender` from the leftovers automatically
3. Check frontend batching the operations for `AngleRouter::mixer` for users not to loose funds

# Report 2
## Title
Direct theft of any user funds creating new vaults

## Description
There is an issue across multiple vaults, allowing malicious users to steal from others performing operations on the vaults.
There are two possibilities to steal user funds from a vault, when they batch multiple operations and create it
(1) `Router::borrower` => `VaultManager::_createVault` operation, or `VaultManager::createVault`-  when creating a vault for other user, the malicious user may reeenter router via `onERC721Received()` hook. This may not be very likely though. But the fact is that even though `VaultManager::angle` is protected against reentrancy, `VaultManager::createVault` is not, and it can lead to a  reentrancy.
(2) Malicious user can create a vault in the middle of batched actions in `Router::mixerVaultManagerPermit`,  which is specially designed to approve Router for managing user's vault for a single transaction in VaultManager is  and `Router::mixerVaultManagerPermit`. That would lead to overtaking whole user vault's assets. If multiple actions are batched together, and one of them creates a vault, another one does a transfer or any action that may lead to arbitrary call to a malicious user, then next one performs some actions on a new user vault (with vaultID = 0), user can create a vault via `VaultManager::createVault` or `VaultManager::angle`, then approve everyone that's required and receive all the assets of different user, because operations on a new vault always have vauldID = 0, which is then set in the VaultManager accordingly. Additionally, I observed that VaultManager::createVault is not protected from reentrancy through "nonReentrant" flag, while if allows for reentrancy via onERC721Received() hook and bypasses reentrancy flag in `VaultManager::angle`.

And concerning probability of such an attack, let's take one of the mainnet transactions as an example:
https://etherscan.io/tx/0xf83beaa0c44bea6bb5eae23d59c2effd7011e50957fcb535c53d10d8500d199e
In this transaction user called the same Vault in two distinct operations. First he creates a vault, adds collateral and borrows stablecoin. In the second transaction they add all remaining balance as collateral. If there was a malicious call in the middle (e.g. via ERC777 transfer), that would allow malicious attacker to perform arbitrary call, they could easily create a vault, and receive all the collateral from the last operation


## Exemplary attack flow
0. Malicious actor creates a malicious contract that creates a vault and approves AngleRouter and victim's address as vault's operators
1. Victim creates following transaction:
- transfer: transfer collateral together with a token susceptible to arbitrary call (e.g. ERC777)
- createVault
- swap: swap tokens for other susceptible ones
- transfer: transfer to a malicious user
- addCollateral: add collateral to a new vault
- borrow: borrow stablecoins from a new vault
2. When transfer to a malicious contract takes place, it creates a vault and approves AngleRouter and victim's address as vault's operators
3. All other operations are performed on the malicious contract's vault, user unknowingly looses their funds.

## Risk Breakdown
Difficulty to Exploit: Medium
Weakness: funds stealing

## Recommended fix
1. add reentrancy flag to `VaultManager::createVault` - this will prevent this attack in VaultManager if invoked directly
2. `AngleRouter::mixer` and `AngleRoutermixerVaultManagerPermit` should have reentrancy flag set, and `mixer` should cache all vauldIDs ahead of time, to prevent malicious user to create a vault in the middle of processing