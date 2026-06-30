// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {Test} from "forge-std-1.16.1/Test.sol";
import {SpaceObject} from "../src/SpaceObject.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.1/access/Ownable.sol";
import {Pausable} from "@openzeppelin-contracts-5.6.1/utils/Pausable.sol";
import {ERC20} from "@openzeppelin-contracts-5.6.1/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract SpaceObjectTest is Test {
    SpaceObject internal so;
    MockERC20 internal token;

    address internal owner = makeAddr("owner");
    address internal solver = makeAddr("solver");
    address internal recipient = makeAddr("recipient");
    bytes32 internal repayment =
        bytes32(uint256(uint160(makeAddr("repayment"))));

    function setUp() public {
        so = new SpaceObject(owner);
        token = new MockERC20();
        token.mint(solver, 1_000_000e18);
        vm.prank(solver);
        token.approve(address(so), type(uint256).max);
    }

    // ---- Helpers ----

    function _relay() internal view returns (SpaceObject.Relay memory r) {
        r = SpaceObject.Relay({
            taker: hex"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            tokenIn: hex"00000000000000000000000000000000000000000000000000000000deadbeef",
            amountIn: 1_000,
            tokenOut: bytes32(uint256(uint160(address(token)))),
            amountOut: 590,
            recipient: bytes32(uint256(uint160(recipient))),
            originChain: 99,
            deadline: uint64(block.timestamp + 3_600),
            nonce: 1
        });
    }

    /// @dev Independent reconstruction of the on-chain preimage (this chain as destination).
    function _id(SpaceObject.Relay memory r) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    r.taker,
                    r.tokenIn,
                    r.amountIn,
                    r.tokenOut,
                    r.amountOut,
                    r.recipient,
                    uint64(block.chainid),
                    r.deadline,
                    r.nonce
                )
            );
    }

    // ---- Construction ----

    function test_ConstructorSetsOwner() public view {
        assertEq(so.owner(), owner);
        assertFalse(so.paused());
    }

    function test_OrderIdForMatchesReconstruction() public view {
        SpaceObject.Relay memory r = _relay();
        assertEq(so.orderIdFor(r), _id(r));
        assertEq(so.orderIdFor(r), so.orderIdFor(r, uint64(block.chainid)));
    }

    // ---- fill: happy path ----

    function test_FillDeliversAndRecords() public {
        SpaceObject.Relay memory r = _relay();
        bytes32 id = _id(r);

        vm.expectEmit(true, true, true, true, address(so));
        emit SpaceObject.OrderFilled(
            id,
            solver,
            99,
            repayment,
            address(token),
            recipient,
            590
        );

        vm.prank(solver);
        so.fill(id, r, repayment);

        assertEq(token.balanceOf(recipient), 590);
        assertTrue(so.isFilled(id));

        SpaceObject.FillReceipt memory receipt = so.fillOf(id);
        assertEq(receipt.solver, solver);
        assertEq(receipt.repaymentAddress, repayment);
        assertEq(receipt.originChain, 99);
        assertEq(receipt.filledAt, uint64(block.timestamp));
    }

    // ---- fill: guards ----

    function test_FillRevertsOnDoubleFill() public {
        SpaceObject.Relay memory r = _relay();
        bytes32 id = _id(r);

        vm.prank(solver);
        so.fill(id, r, repayment);

        vm.prank(solver);
        vm.expectRevert(
            abi.encodeWithSelector(SpaceObject.OrderAlreadyFilled.selector, id)
        );
        so.fill(id, r, repayment);
    }

    function test_FillRevertsWhenExpired() public {
        SpaceObject.Relay memory r = _relay();
        r.deadline = uint64(block.timestamp);
        bytes32 id = _id(r);

        vm.warp(block.timestamp + 1);

        vm.prank(solver);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpaceObject.OrderExpired.selector,
                r.deadline
            )
        );
        so.fill(id, r, repayment);
    }

    function test_FillRevertsOnIdMismatch() public {
        SpaceObject.Relay memory r = _relay();
        bytes32 wrongId = keccak256("not the right id");

        vm.prank(solver);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpaceObject.OrderIdMismatch.selector,
                wrongId,
                _id(r)
            )
        );
        so.fill(wrongId, r, repayment);
    }

    /// @dev A different chain id changes the destination commitment, so the order
    /// is unfillable here even though every other field is identical.
    function test_FillRevertsOnWrongDestinationChain() public {
        SpaceObject.Relay memory r = _relay();
        bytes32 foreignId = so.orderIdFor(r, uint64(block.chainid) + 1);

        vm.prank(solver);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpaceObject.OrderIdMismatch.selector,
                foreignId,
                _id(r)
            )
        );
        so.fill(foreignId, r, repayment);
    }

    function test_FillRevertsOnNonCanonicalRecipient() public {
        SpaceObject.Relay memory r = _relay();
        r.recipient = bytes32(type(uint256).max);
        bytes32 id = _id(r);

        vm.prank(solver);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpaceObject.InvalidAddressEncoding.selector,
                r.recipient
            )
        );
        so.fill(id, r, repayment);
    }

    function test_FillRevertsWhenPaused() public {
        SpaceObject.Relay memory r = _relay();
        bytes32 id = _id(r);

        vm.prank(owner);
        so.pause();

        vm.prank(solver);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        so.fill(id, r, repayment);
    }

    // ---- admin ----

    function test_PauseAndUnpause() public {
        vm.prank(owner);
        so.pause();
        assertTrue(so.paused());

        vm.prank(owner);
        so.unpause();
        assertFalse(so.paused());
    }

    function test_PauseOnlyOwner() public {
        vm.prank(solver);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                solver
            )
        );
        so.pause();
    }
}
