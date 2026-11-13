// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Demo only: a vault with two planted bugs, a reentrant withdraw and an
/// owner anyone can replace. Never deploy this.
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
