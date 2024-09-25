# Damn Vulnerable DeFi v4 Walkthorugh

## 1.UNSTOPPABLE
Starting with 10 DVT tokens in balance, show that it’s possible to halt the vault. It must stop offering flash loans. _See [challenges/unstoppable/](https://www.damnvulnerabledefi.xyz/challenges/unstoppable/)_

### Attack Analysis
Objective: Prevent `UnstoppableVault.flashLoan()` from successfully executing.

The balance of `UnstoppableVault` is not accounted for unexpected changes (e.g. an ERC20 transfer), by just transfering an small amount to the vault, the below condition fail and revert

https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/84b762cb27b1c44cbd2f1ba6caeaaa2805d12a69/src/unstoppable/UnstoppableVault.sol#L84-L85

### PoC

```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), 1e18);
}
```
_See [test/unstoppable/Unstoppable.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/unstoppable/Unstoppable.t.sol)_

----
