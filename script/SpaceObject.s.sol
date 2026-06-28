// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.29;

import {Script} from "forge-std-1.16.1/Script.sol";
import {SpaceObject} from "../src/SpaceObject.sol";

contract SpaceObjectScript is Script {
    SpaceObject public spaceObject;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        spaceObject = new SpaceObject(msg.sender);

        vm.stopBroadcast();
    }
}
