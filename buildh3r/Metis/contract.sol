// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MessageStorage {
    string private message;
    address public owner;
    uint public updateCount;

    event MessageUpdated(string oldMessage, string newMessage, address updatedBy);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can perform this action");
        _;
    }

    constructor(string memory initialMessage) {
        message = initialMessage;
        owner = msg.sender;
        updateCount = 0;
    }

    function setMessage(string memory newMessage) public onlyOwner {
        string memory oldMessage = message;
        message = newMessage;
        updateCount++;
        emit MessageUpdated(oldMessage, newMessage, msg.sender);
    }

    function getMessage() public view returns (string memory) {
        return message;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "New owner cannot be the zero address");
        owner = newOwner;
    }
}
