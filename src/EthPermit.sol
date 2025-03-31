// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.28;

import {IWETH} from "./interfaces/IWETH.sol";

contract EthPermit {
    struct Storage {
        uint256 nonce;
    }

    uint256 private constant _STORAGE_SLOT = uint256(keccak256("EthPermit")) - 0xff;

    bytes32 private constant _DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 private constant _ETH_PERMIT_TYPEHASH =
        keccak256("EthPermit(address owner,address spender,uint256 wrap,uint256 value,uint256 nonce,uint256 deadline)");

    address private immutable _SELF;
    address private immutable _WETH;

    error Expired();
    error InvalidSignature();
    error NotDelegated();

    constructor(address weth) {
        _SELF = address(this);
        _WETH = weth;
    }

    function permit(address spender, uint256 wrap, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external
    {
        require(deadline >= block.timestamp, Expired());
        bytes32 permitHash = getEthPermitHash(address(this), spender, wrap, value, _useNonce(), deadline);
        address recovered = ecrecover(permitHash, v, r, s);
        require(recovered == address(this), InvalidSignature());

        _wrap(wrap);
        _approve(spender, value);
    }

    function getNonce() external view returns (uint256) {
        require(address(this) != _SELF, NotDelegated());
        return _$().nonce;
    }

    function getDomainSeparator() public view returns (bytes32 domainSeparator) {
        bytes32 domainTypehash = _DOMAIN_TYPEHASH;
        address self = _SELF;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, domainTypehash)
            mstore(add(ptr, 0x20), chainid())
            mstore(add(ptr, 0x40), self)
            domainSeparator := keccak256(ptr, 0x60)
        }
        return domainSeparator;
    }

    function getEthPermitHash(
        address owner,
        address spender,
        uint256 wrap,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32 permitHash) {
        bytes32 ethPermitTypehash = _ETH_PERMIT_TYPEHASH;
        bytes32 domainSeparator = getDomainSeparator();
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, ethPermitTypehash)
            mstore(add(ptr, 0x20), owner)
            mstore(add(ptr, 0x40), spender)
            mstore(add(ptr, 0x60), wrap)
            mstore(add(ptr, 0x80), value)
            mstore(add(ptr, 0xa0), nonce)
            mstore(add(ptr, 0xc0), deadline)
            mstore(add(ptr, 0x22), keccak256(ptr, 0xe0))
            mstore(ptr, hex"1901")
            mstore(add(ptr, 0x02), domainSeparator)
            permitHash := keccak256(ptr, 0x42)
        }
    }

    function _useNonce() private returns (uint256) {
        unchecked {
            return _$().nonce++;
        }
    }

    function _wrap(uint256 amount) private {
        if (amount == type(uint256).max) {
            amount = address(this).balance;
        }
        if (amount > 0) {
            address weth = _WETH;
            assembly ("memory-safe") {
                mstore(0, hex"d0e30db0")
                pop(call(gas(), weth, amount, 0, 4, 0, 0))
            }
        }
    }

    function _approve(address spender, uint256 amount) private {
        address weth = _WETH;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, hex"095ea7b3")
            mstore(add(ptr, 0x04), spender)
            mstore(add(ptr, 0x24), amount)
            pop(call(gas(), weth, 0, ptr, add(ptr, 0x44), 0, 0))
        }
    }

    function _$() private pure returns (Storage storage $) {
        uint256 slot = _STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }
}
