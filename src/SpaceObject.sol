// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {Ownable} from "@openzeppelin-contracts-5.6.1/access/Ownable.sol";
import {Pausable} from "@openzeppelin-contracts-5.6.1/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin-contracts-5.6.1/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin-contracts-5.6.1/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts-5.6.1/token/ERC20/utils/SafeERC20.sol";

/// @title SpaceObject — destination-chain settlement for a cross-chain intent bridge.
/// @notice Counterpart to the source-chain escrow (see the Soroban `space-object`
/// contract). On the source chain a taker locks `amount_in` of `token_in` and
/// commits to an order whose id is `keccak256` over its terms. On this
/// destination chain a solver calls {fill}: it delivers the promised `amountOut`
/// of `tokenOut` to the `recipient`, and the contract records the
/// `repaymentAddress` the solver should later be repaid at on the origin chain.
/// @dev The order id is a cross-chain commitment. {fill} rebuilds the exact
/// preimage the source chain hashed — substituting this chain's id for the
/// order's `dest_chain` — so a match simultaneously proves the relayed terms are
/// authentic and that the order targets this chain. The byte layout must mirror
/// the source `order_id` implementation byte-for-byte.
contract SpaceObject is Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice An order's terms as seen from the destination chain.
    /// @dev Mirrors the source-chain `Order` field-for-field, except `dest_chain`
    /// is replaced by {originChain}: the destination is implicit (it is this
    /// chain), whereas the origin must be carried so the later origin-chain
    /// repayment can be routed. {originChain} is metadata only — it is NOT part of
    /// the order-id preimage (the source order commits to `dest_chain`, not the
    /// origin). `taker` and `tokenIn` are origin-chain (Stellar) identifiers
    /// carried as the raw 32-byte payload the origin chain committed to — the
    /// ed25519 key of a `G…` account or the contract-id hash of a `C…` contract,
    /// with no XDR framing. `tokenOut` and `recipient` are this chain's addresses
    /// in 32-byte form (left-padded, high bytes zero).
    struct Relay {
        bytes32 taker;
        bytes32 tokenIn;
        uint128 amountIn;
        bytes32 tokenOut;
        uint128 amountOut;
        bytes32 recipient;
        uint64 originChain;
        uint64 deadline;
        uint64 nonce;
    }

    /// @notice Record written when an order is filled; `filledAt == 0` means unfilled.
    struct FillReceipt {
        address solver;
        bytes32 repaymentAddress;
        uint64 originChain;
        uint64 filledAt;
    }

    /// @dev Fills keyed by order id; one fill per id (replay protection).
    mapping(bytes32 orderId => FillReceipt receipt) private _fills;

    /// @notice Emitted once per order when a solver settles it on this chain.
    event OrderFilled(
        bytes32 indexed orderId,
        address indexed solver,
        uint64 indexed originChain,
        bytes32 repaymentAddress,
        address tokenOut,
        address recipient,
        uint256 amountOut
    );

    /// @notice The order's fill deadline has already passed.
    error OrderExpired(uint64 deadline);
    /// @notice The relayed terms (with this chain as destination) do not hash to `orderId`.
    error OrderIdMismatch(bytes32 expected, bytes32 computed);
    /// @notice The order id has already been filled.
    error OrderAlreadyFilled(bytes32 orderId);
    /// @notice A 32-byte field does not encode a canonical EVM address (high bytes set).
    error InvalidAddressEncoding(bytes32 word);

    /// @param initialOwner Account granted ownership (pause control).
    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Settles an order on this destination chain.
    /// @dev Validates the order, blocks double fills, records the fill, then has
    /// the solver (`msg.sender`) deliver `amountOut` of `tokenOut` to `recipient`.
    /// The `repaymentAddress` is recorded as-is and never validated: if a solver
    /// supplies a wrong one, the loss of their origin-chain repayment is on them.
    /// The order `nonce` is a source-chain concern and is not checked here.
    /// @param orderId The source-chain content id of the order.
    /// @param relay The order's terms (see {Relay}).
    /// @param repaymentAddress Where the solver wants to be repaid on the origin chain.
    function fill(
        bytes32 orderId,
        Relay calldata relay,
        bytes32 repaymentAddress
    ) external whenNotPaused nonReentrant {
        // 1. The order must still be live.
        if (block.timestamp > relay.deadline) {
            revert OrderExpired(relay.deadline);
        }

        // 2 & 3. Rebuild the content id, pinning the destination to THIS chain. A
        // match proves the relayed terms are authentic AND that the order's
        // `dest_chain` equals `block.chainid` (i.e. it targets this chain).
        bytes32 computed = _orderId(relay, uint64(block.chainid));
        if (computed != orderId) {
            revert OrderIdMismatch(orderId, computed);
        }

        // 4. One fill per order id.
        if (_fills[orderId].filledAt != 0) {
            revert OrderAlreadyFilled(orderId);
        }

        // Effects: record the fill before the external transfer (CEI + nonReentrant).
        uint64 originChain = relay.originChain;
        _fills[orderId] = FillReceipt({
            solver: msg.sender,
            repaymentAddress: repaymentAddress,
            originChain: originChain,
            filledAt: uint64(block.timestamp)
        });

        address tokenOut = _toAddress(relay.tokenOut);
        address recipient = _toAddress(relay.recipient);
        uint256 amountOut = relay.amountOut;

        // Interaction: the solver delivers the promised output to the recipient.
        IERC20(tokenOut).safeTransferFrom(msg.sender, recipient, amountOut);

        emit OrderFilled(
            orderId,
            msg.sender,
            originChain,
            repaymentAddress,
            tokenOut,
            recipient,
            amountOut
        );
    }

    /// @notice Order id for `relay` as filled on THIS chain (uses `block.chainid`).
    function orderIdFor(Relay calldata relay) external view returns (bytes32) {
        return _orderId(relay, uint64(block.chainid));
    }

    /// @notice Order id for `relay` against an explicit `destChain` (off-chain tooling).
    function orderIdFor(
        Relay calldata relay,
        uint64 destChain
    ) external pure returns (bytes32) {
        return _orderId(relay, destChain);
    }

    /// @notice The fill record for `orderId` (zeroed `FillReceipt` if unfilled).
    function fillOf(
        bytes32 orderId
    ) external view returns (FillReceipt memory) {
        return _fills[orderId];
    }

    /// @notice Whether `orderId` has been filled.
    function isFilled(bytes32 orderId) external view returns (bool) {
        return _fills[orderId].filledAt != 0;
    }

    /// @notice Pauses {fill}. Owner only.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Resumes {fill}. Owner only.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @dev Content id: `keccak256` over the fixed-layout preimage of the order's
    /// terms. Layout, concatenated with no padding or length prefixes:
    /// `taker:32 ‖ tokenIn:32 ‖ amountIn:be16 ‖ tokenOut:32 ‖ amountOut:be16 ‖
    /// recipient:32 ‖ destChain:be8 ‖ deadline:be8 ‖ nonce:be8`.
    /// This must match the source-chain `order_id` byte-for-byte.
    function _orderId(
        Relay calldata relay,
        uint64 destChain
    ) private pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    relay.taker,
                    relay.tokenIn,
                    relay.amountIn,
                    relay.tokenOut,
                    relay.amountOut,
                    relay.recipient,
                    destChain,
                    relay.deadline,
                    relay.nonce
                )
            );
    }

    /// @dev Narrows a 32-byte field to an EVM address, reverting unless it is a
    /// canonical left-padded encoding (high 12 bytes zero).
    function _toAddress(bytes32 word) private pure returns (address) {
        if (uint256(word) >> 160 != 0) {
            revert InvalidAddressEncoding(word);
        }
        return address(uint160(uint256(word)));
    }
}
