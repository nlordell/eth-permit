// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.28;

import {Test, Vm, console} from "forge-std/Test.sol";
import {EthPermit} from "../src/EthPermit.sol";
import {IWETH} from "../src/interfaces/IWETH.sol";
import {Bytecode} from "./utils/Bytecode.sol";

contract EthPermitTest is Test {
    IWETH weth;
    EthPermit ethPermit;

    Vm.Wallet account;
    Vm.Wallet beneficiary;
    Vm.Wallet relayer;

    constructor() {
        weth = IWETH(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
        ethPermit = new EthPermit(address(weth));
        account = vm.createWallet("account");
        beneficiary = vm.createWallet("beneficiary");
        relayer = vm.createWallet("relayer");
    }

    function setUp() public {
        vm.etch(address(weth), Bytecode.WETH9);
        vm.deal(account.addr, 1 ether);
        vm.signAndAttachDelegation(address(ethPermit), account.privateKey);
    }

    function test_permit() public {
        bytes32 permitHash = ethPermit.getEthPermitHash(
            account.addr, beneficiary.addr, 0.1 ether, 0.05 ether, EthPermit(account.addr).getNonce(), type(uint256).max
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(account.privateKey, permitHash);

        vm.expectCall(address(weth), 0.1 ether, abi.encodeCall(IWETH.deposit, ()));
        vm.expectCall(address(weth), 0, abi.encodeCall(IWETH.approve, (beneficiary.addr, 0.05 ether)));
        vm.prank(relayer.addr);
        EthPermit(account.addr).permit(beneficiary.addr, 0.1 ether, 0.05 ether, type(uint256).max, v, r, s);

        assertEq(account.addr.balance, 0.9 ether);
        assertEq(weth.balanceOf(account.addr), 0.1 ether);
        assertEq(weth.allowance(account.addr, beneficiary.addr), 0.05 ether);
    }

    function test_permitNoWrap() public {
        bytes32 permitHash = ethPermit.getEthPermitHash(
            account.addr, beneficiary.addr, 0, 0, EthPermit(account.addr).getNonce(), type(uint256).max
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(account.privateKey, permitHash);

        vm.expectCall(address(weth), abi.encodeCall(IWETH.deposit, ()), 0);
        vm.expectCall(address(weth), 0, abi.encodeCall(IWETH.approve, (beneficiary.addr, 0)));
        vm.prank(relayer.addr);
        EthPermit(account.addr).permit(beneficiary.addr, 0, 0, type(uint256).max, v, r, s);
    }

    function test_permitWrapAll() public {
        bytes32 permitHash = ethPermit.getEthPermitHash(
            account.addr,
            beneficiary.addr,
            type(uint256).max,
            type(uint256).max,
            EthPermit(account.addr).getNonce(),
            type(uint256).max
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(account.privateKey, permitHash);

        vm.expectCall(address(weth), account.addr.balance, abi.encodeCall(IWETH.deposit, ()));
        vm.expectCall(address(weth), 0, abi.encodeCall(IWETH.approve, (beneficiary.addr, type(uint256).max)));
        vm.prank(relayer.addr);
        EthPermit(account.addr).permit(
            beneficiary.addr, type(uint256).max, type(uint256).max, type(uint256).max, v, r, s
        );
    }

    function test_permitExpires() public {
        uint256 expiration = block.timestamp + 1 hours;
        bytes32 permitHash = ethPermit.getEthPermitHash(
            account.addr, beneficiary.addr, 0, 0, EthPermit(account.addr).getNonce(), expiration
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(account.privateKey, permitHash);

        vm.startPrank(relayer.addr);
        uint256 snapshot = vm.snapshotState();

        EthPermit(account.addr).permit(beneficiary.addr, 0, 0, expiration, v, r, s);

        vm.revertToState(snapshot);

        vm.warp(expiration);
        EthPermit(account.addr).permit(beneficiary.addr, 0, 0, expiration, v, r, s);

        vm.revertToStateAndDelete(snapshot);

        vm.warp(expiration + 1);
        vm.expectRevert(EthPermit.Expired.selector);
        EthPermit(account.addr).permit(beneficiary.addr, 0, 0, expiration, v, r, s);
    }

    function test_permitReplayProtection() public {
        uint256 nonce = EthPermit(account.addr).getNonce();
        bytes32 permitHash = ethPermit.getEthPermitHash(account.addr, beneficiary.addr, 0, 0, nonce, type(uint256).max);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(account.privateKey, permitHash);

        vm.startPrank(relayer.addr);
        EthPermit(account.addr).permit(beneficiary.addr, 0, 0, type(uint256).max, v, r, s);

        assertEq(EthPermit(account.addr).getNonce(), nonce + 1);

        vm.expectRevert(EthPermit.InvalidSignature.selector);
        EthPermit(account.addr).permit(beneficiary.addr, 0, 0, type(uint256).max, v, r, s);
    }

    function test_permitInvalidSignature() public {
        bytes32 permitHash = ethPermit.getEthPermitHash(
            account.addr,
            beneficiary.addr,
            type(uint256).max,
            type(uint256).max,
            EthPermit(account.addr).getNonce(),
            type(uint256).max
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(account.privateKey, permitHash);

        vm.expectRevert(EthPermit.InvalidSignature.selector);
        vm.prank(relayer.addr);
        EthPermit(account.addr).permit(relayer.addr, type(uint256).max, type(uint256).max, type(uint256).max, v, r, s);
    }

    function test_getNonceDelegation() public {
        EthPermit(account.addr).getNonce();

        vm.expectRevert(EthPermit.NotDelegated.selector);
        ethPermit.getNonce();
    }

    function test_getDomainSeparator() public view {
        assertEq(
            ethPermit.getDomainSeparator(),
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
                    block.chainid,
                    address(ethPermit)
                )
            )
        );
    }

    function test_getEthPermitHash() public view {
        assertEq(
            ethPermit.getEthPermitHash(
                0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa,
                0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB,
                4.2 ether,
                13.37 ether,
                42,
                123456789
            ),
            keccak256(
                abi.encodePacked(
                    hex"1901",
                    keccak256(
                        abi.encode(
                            keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
                            block.chainid,
                            address(ethPermit)
                        )
                    ),
                    keccak256(
                        abi.encode(
                            keccak256(
                                "EthPermit(address owner,address spender,uint256 wrap,uint256 value,uint256 nonce,uint256 deadline)"
                            ),
                            0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa,
                            0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB,
                            4.2 ether,
                            13.37 ether,
                            42,
                            123456789
                        )
                    )
                )
            )
        );
    }
}
