# Spearbit Technical Assessment

# Findings 

## Griefing attack by destroying Implementation contract

**Severity**: High

Context: [`Implementation.sol#L9-L22`](https://github.com/spearbit-audits/writing-exercise/blob/de45a4c5b654710812e9fa29dde6e12526fe4786/contracts/Implementation.sol#L9-L22)

Implementation contract can be destroyed by calling selfdestruct() under a delegatecall function. All funds of Proxy contract will be frozen when Implementation contract will be destroyed by a malicious actor.

**Recommendation**: Change contract to a library and remove payable keywords.

```diff
-contract Implementation {
+library Implementation {
-    function callContract(address a, bytes calldata _calldata) payable external returns (bytes memory) {
+    function callContract(address a, bytes calldata _calldata) external returns (bytes memory) {
        (bool success , bytes memory ret) =  a.call{value: msg.value}(_calldata);
        require(success);
        return ret;
    }

-    function delegatecallContract(address a, bytes calldata _calldata) payable external returns (bytes memory) {
+    function delegatecallContract(address a, bytes calldata _calldata) external returns (bytes memory) {
```

**Solution that checks first storage slot**:
```diff
contract Implementation {

    function callContract(address a, bytes calldata _calldata) payable external returns (bytes memory) {
        (bool success , bytes memory ret) =  a.call{value: msg.value}(_calldata);
        require(success);
        return ret;
    }

    function delegatecallContract(address a, bytes calldata _calldata) payable external returns (bytes memory) {
+       bytes32 firstSlot;
+       assembly {
+           firstSlot := sload(0x00)
+       }
+       require(firstSlot != 0x00, "first slot should not be empty! Wrong context!");
        
        (bool success, bytes memory ret) =  a.delegatecall(_calldata);
        require(success);
        return ret;
    }
}
```

**Solution that mimics libraries**:
```diff
contract Implementation {

+   address public immutable implAddress;
+   constructor() {                 
+       implAddress = address(this);       
+   } 

    function callContract(address a, bytes calldata _calldata) payable external returns (bytes memory) {
        (bool success , bytes memory ret) =  a.call{value: msg.value}(_calldata);
        require(success);
        return ret;
    }

    function delegatecallContract(address a, bytes calldata _calldata) payable external returns (bytes memory) {
+       require(address(this) != implAddress, "Wrong context!");
        (bool success, bytes memory ret) =  a.delegatecall(_calldata);
        require(success);
        return ret;
    }
}
```
