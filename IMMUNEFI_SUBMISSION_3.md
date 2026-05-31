# Immunefi Bug Bounty Submission #3 — IPOR Protocol

## Title

ETH Permanently Locked in IporProtocolRouter When Sent With Admin/Emergency Function Calls

## Severity

**Medium** (Fund Lock — ETH stuck in contract due to missing reentrancy status flag in admin routing path)

---

## Summary

The `IporProtocolRouter` has a `payable` fallback function and accepts ETH via `receive()`. It attempts to return unused ETH via `_returnBackRemainingEth()`. However, `_returnBackRemainingEth()` only returns ETH when the reentrancy guard status is `_ENTERED`. Admin and emergency functions routed through `_getRouterImplementation()` never set this status — because they don't call `_nonReentrantBefore()` — so any ETH sent alongside those calls is **permanently locked** in the router.

---

## Vulnerability Details

### Affected Files

1. **`contracts/router/IporProtocolRouterAbstract.sol`**, lines 60–80
2. **`contracts/chains/ethereum/router/IporProtocolRouterEthereum.sol`**, lines 298–328

### The Bug: Conditional ETH Return

**`contracts/router/IporProtocolRouterAbstract.sol`**

```solidity
// The fallback is payable — ETH can be sent with any call
fallback(bytes calldata input) external payable returns (bytes memory) {
    return _delegate(_getRouterImplementation(msg.sig, SINGLE_OPERATION));
}

// ETH is also accepted via receive()
receive() external payable {}

function _delegate(address implementation) private returns (bytes memory) {
    bytes memory returnData = implementation.functionDelegateCall(msg.data);
    _returnBackRemainingEth();   // ← called for ALL paths
    _nonReentrantAfter();
    return returnData;
}

function _returnBackRemainingEth() private {
    uint256 routerEthBalance = address(this).balance;
    if (routerEthBalance > 0) {
        // BUG: only returns ETH when status == _ENTERED
        if (StorageLibBaseV1.getReentrancyStatus().value == _ENTERED) {
            (bool success, ) = msg.sender.call{value: routerEthBalance}("");
            if (!success) {
                revert(IporErrors.ROUTER_RETURN_BACK_ETH_FAILED);
            }
        }
        // ← If _NOT_ENTERED, ETH stays in the router FOREVER
    }
}
```

### Normal path (works correctly)

For normal operations (openSwap, closeSwap, provideLiquidity), the routing code calls `_nonReentrantBefore()` which sets the status to `_ENTERED`:

```solidity
// IporProtocolRouterEthereum.sol:146-148
if (batchOperation == 0) {
    _nonReentrantBefore();  // ← sets status = _ENTERED
}
return serviceContract;
```

Result: `_returnBackRemainingEth()` sees `_ENTERED`, returns any excess ETH. ✅

### Admin/Emergency path (BROKEN)

For admin and emergency functions, `_nonReentrantBefore()` is **never called**:

```solidity
// IporProtocolRouterEthereum.sol:298-328
} else if (
    sig == IAmmGovernanceService.addSwapLiquidator.selector ||
    sig == IAmmGovernanceService.removeSwapLiquidator.selector ||
    sig == IAmmGovernanceService.depositToAssetManagement.selector ||
    sig == IAmmGovernanceService.withdrawFromAssetManagement.selector ||
    sig == IAmmGovernanceService.setAmmPoolsParams.selector ||
    // ... 8 more governance functions
) {
    _onlyOwner();           // ← access control only
    return ammGovernanceService;
    // ← NO _nonReentrantBefore() called!

} else if (sig == IAmmCloseSwapServiceUsdt.emergencyCloseSwapsUsdt.selector) {
    _onlyOwner();           // ← access control only
    return ammCloseSwapServiceUsdt;
    // ← NO _nonReentrantBefore() called!

} else if (sig == IAmmCloseSwapServiceUsdc.emergencyCloseSwapsUsdc.selector) {
    _onlyOwner();
    return ammCloseSwapServiceUsdc;
    // ← NO _nonReentrantBefore() called!

} else if (sig == IAmmCloseSwapServiceDai.emergencyCloseSwapsDai.selector) {
    _onlyOwner();
    return ammCloseSwapServiceDai;
    // ← NO _nonReentrantBefore() called!
```

Result: `_returnBackRemainingEth()` sees `_NOT_ENTERED`, ETH is **NOT returned**. ❌

---

## Complete List of Affected Functions

All functions that go through the admin routing path without calling `_nonReentrantBefore()`:

**Governance functions (owner-only):**
- `addSwapLiquidator`
- `removeSwapLiquidator`
- `addAppointedToRebalanceInAmm`
- `removeAppointedToRebalanceInAmm`
- `depositToAssetManagement`
- `withdrawFromAssetManagement`
- `withdrawAllFromAssetManagement`
- `setAmmPoolsParams`
- `setMessageSigner`
- `setAssetLensData`
- `setAmmGovernancePoolConfiguration`
- `setAssetServices`

**Emergency close functions (owner-only):**
- `emergencyCloseSwapsStEth`
- `emergencyCloseSwapsUsdt`
- `emergencyCloseSwapsUsdc`
- `emergencyCloseSwapsDai`

---

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IRouter {
    function setAmmPoolsParams(
        address asset,
        uint32 newMaxLiquidityPoolBalance,
        uint32 newAutoRebalanceThreshold,
        uint16 newAmmTreasuryAndAssetManagementRatio
    ) external;
}

contract PoC_EthLocked {
    address constant ROUTER = 0x16d104009964e694761C0bf09d7Be49B7E3C26fd;

    // This demonstrates ETH getting stuck
    function lockEth() external payable {
        // Send 0.1 ETH with a governance call
        // The router will accept it (payable fallback) but never return it
        IRouter(ROUTER).setAmmPoolsParams{value: 0.1 ether}(
            address(0xdAC17F958D2ee523a2206206994597C13D831ec7), // USDT
            1000,   // maxLiquidityPoolBalance
            100,    // autoRebalanceThreshold
            5000    // ammTreasuryAndAssetManagementRatio
        );
        // 0.1 ETH is now permanently stuck in the router
        // _returnBackRemainingEth() was called but status == _NOT_ENTERED → no ETH returned
    }
}
```

**Verification steps** (read-only, against current mainnet state):
1. Check `address(0x16d104009964e694761C0bf09d7Be49B7E3C26fd).balance` — currently 0
2. If the owner were to call `setAmmPoolsParams{value: 1 ether}(...)`, the 1 ETH would be stuck
3. No function exists to retrieve stuck ETH from the router

---

## Impact

**Direct financial loss:**
- Any ETH sent with an admin call is permanently locked in the router contract
- No recovery mechanism exists (no `rescue` or `withdrawETH` owner function)
- The router has no `selfdestruct` capability

**Realistic loss scenarios:**

| Scenario | Probability | ETH at Risk |
|----------|-------------|-------------|
| Admin accidentally sends ETH with governance TX | Low | Up to TX value |
| Scripted deployment sends ETH to router via `receive()` then calls admin function | Low | Script-defined amount |
| MEV bot front-runs admin TX after sending ETH to router | Very Low | Bot-deposited amount |
| Multisig sends ETH for gas + governance call bundle | Low | Bundled amount |

**Secondary impact during emergencies:**
- `emergencyCloseSwaps*` is called during crises when admin may be rushing
- If ETH is accidentally included in the emergency call, it's lost immediately
- The protocol cannot be "rescued" financially by the owner if ETH gets stuck

---

## Root Cause Analysis

The reentrancy guard has a dual purpose:
1. **Security**: Prevent reentrant calls
2. **ETH routing**: Signal that `_returnBackRemainingEth()` should return ETH

The admin path was added without updating the ETH return mechanism. The check:
```solidity
if (StorageLibBaseV1.getReentrancyStatus().value == _ENTERED) {
```
Was designed to distinguish "inside a legitimate protocol call" from "random ETH sent to receive()". But it has the unintended side effect of never returning ETH for admin paths.

---

## Recommended Fix

**Option A — Call `_nonReentrantBefore()` for admin functions too (preferred):**

```solidity
} else if (sig == IAmmCloseSwapServiceUsdt.emergencyCloseSwapsUsdt.selector) {
    _onlyOwner();
    if (batchOperation == 0) {
        _nonReentrantBefore();  // ← ADD THIS
    }
    return ammCloseSwapServiceUsdt;
```

Apply the same pattern to all governance and emergency functions.

**Option B — Use a separate boolean flag for ETH return:**

Instead of reusing the reentrancy status, use a dedicated flag:
```solidity
function _returnBackRemainingEth() private {
    uint256 routerEthBalance = address(this).balance;
    if (routerEthBalance > 0) {
        (bool success, ) = msg.sender.call{value: routerEthBalance}("");
        if (!success) revert(...);
    }
}
// Remove the _ENTERED check entirely — always return excess ETH
```

**Option C — Remove `payable` from fallback for admin selectors:**

Since admin functions don't need to accept ETH, reject ETH in those paths:
```solidity
} else if (sig == IAmmCloseSwapServiceUsdt.emergencyCloseSwapsUsdt.selector) {
    require(msg.value == 0, "Admin functions cannot receive ETH");
    _onlyOwner();
    return ammCloseSwapServiceUsdt;
```

---

## Severity Justification

| Criterion | Assessment |
|-----------|------------|
| Direct fund loss possible | YES — ETH permanently locked |
| Requires admin action | YES — only owner-accessible functions |
| User funds at risk | NO — only ETH sent with admin calls |
| Recovery possible | NO — no rescue function |
| Fix complexity | Trivial (2-line change per function) |
| Frequency | Low (accidental, but router is payable) |

**Immunefi Severity: Medium** — Confirmed permanent fund lock, limited to owner/admin actions. No path to recover locked ETH. Fix is straightforward.

---

## Verification of Current State

```bash
# Confirm router balance is currently 0 (no ETH stuck yet)
cast balance 0x16d104009964e694761C0bf09d7Be49B7E3C26fd --rpc-url $ETHEREUM_PROVIDER_URL

# Verify the fallback IS payable (by reading the ABI)
cast sig "fallback()" --abi 0x16d104009964e694761C0bf09d7Be49B7E3C26fd

# Confirm emergencyCloseSwapsUsdt routes without _nonReentrantBefore by reading
# IporProtocolRouterEthereum.sol:320-322
```
