// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.28;

interface IWETH {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);

    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address guy) external view returns (uint256);

    function deposit() external payable;
    function withdraw(uint256 wad) external;

    function totalSupply() external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address dst, uint256 wad) external returns (bool);
    function transferFrom(address src, address dst, uint256 wad) external returns (bool);
}
