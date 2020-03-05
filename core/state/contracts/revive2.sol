pragma solidity ^0.6.0;

// solc --allow-paths ., --abi --bin --overwrite --optimize -o core/state/contracts/build core/state/contracts/revive2.sol
// abigen -abi core/state/contracts/build/Revive2.abi -bin core/state/contracts/build/Revive2.bin -pkg contracts -type revive2 -out core/state/contracts/gen_revive2.go
// abigen -abi core/state/contracts/build/Phoenix.abi -bin core/state/contracts/build/Phoenix.bin -pkg contracts -type phoenix -out core/state/contracts/gen_phoenix.go
contract Revive2 {

    constructor() public {
    }

    event DeployEvent (Phoenix d);

    /* Deploys self-destructing contract with given salt and emits DeployEvent with the address of the created contract */
    function deploy(bytes32 salt) public {
        Phoenix d;
        d = new Phoenix{salt: salt}();
        emit DeployEvent(d);
    }
}

contract Phoenix {
    uint256 location;
    mapping(uint256=>uint256) data;
    
    constructor() public {
    }

    function store() public {
        data[location] = 1;
        location++;
    }

    receive() external payable {
    }

    function die() public {
        selfdestruct(address(0));
    }
}