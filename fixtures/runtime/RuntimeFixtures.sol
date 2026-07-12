// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract RuntimeERC20 {
    mapping(address => uint256) public balanceOf;

    constructor(address recipient, uint256 amount) {
        balanceOf[recipient] = amount;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

contract RuntimeNFT {
    mapping(uint256 => address) public ownerOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    constructor() {
        ownerOf[1] = msg.sender;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "WRONG_FROM");
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "NOT_AUTHORIZED");
        ownerOf[tokenId] = to;
    }
}
