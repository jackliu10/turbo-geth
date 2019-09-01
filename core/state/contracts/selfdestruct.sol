pragma solidity ^0.5.0;

// solc --allow-paths ., --abi --bin --overwrite --optimize -o core/state/contracts/build core/state/contracts/selfdestruct.sol
// ./build/bin/abigen -abi core/state/contracts/build/Selfdestruct.abi -bin core/state/contracts/build/Selfdestruct.bin -pkg contracts -type selfdestruct -out core/state/contracts/gen_selfdestruct.go
contract Selfdestruct {

    uint256 x;
    uint256 y;
    uint256 z;

    constructor() public {
        // Fill some storage positions
        x = 1;
        y = 2;
        z = 3;
    }

    function () external payable {}

    /* Self-destructs */
    function destruct() public {
        selfdestruct(address(this));
    }
}
