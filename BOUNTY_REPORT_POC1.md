# Bug Bounty Report — IPOR Protocol
## Finding: Arithmetic Underflow in `calculateLpDepth` Blocks Swap Openings and Unwind of Existing Positions

**Severity:** High  
**Asset:** IPOR Protocol — Ethereum Mainnet  
**Contracts:** SpreadRouter (`0xAc1C86CEacf03d5AFC8b08A22fc38Ec7c72338ed`), Spread28Days (`0xb8d531ea16CAF1CF7B7cBC333E8963dB59E8dAD5`), Spread60Days (`0x36618cE1615305f3b99eeB9dF8d4272E729A81aB`), Spread90Days (`0x22C1CF8FCDE74A373791863953B8C9aB417795D5`)  
**Vulnerable File:** `contracts/amm/spread/CalculateTimeWeightedNotionalLibs.sol`, line 19  
**Secondary File:** `contracts/base/spread/CalculateTimeWeightedNotionalLibsBaseV1.sol`, line 19  

---

## Summary

`CalculateTimeWeightedNotionalLibs.calculateLpDepth()` performs an unchecked subtraction in Solidity 0.8.26, which uses checked arithmetic by default. When the on-chain market state reaches `totalCollateralPayFixed > liquidityPoolBalance + totalCollateralReceiveFixed`, the subtraction underflows and triggers a `Panic(0x11)` revert.

This revert propagates through **two distinct call paths**:

1. **Opening new swaps** — all new pay-fixed and receive-fixed swap openings across all tenors (28/60/90 days) revert.
2. **Early closure with unwind of existing positions** — users holding active swaps who attempt to close before maturity via the unwind mechanism cannot exit their positions for the remainder of the swap tenure (up to 89 days for a 90-day swap).

The condition arises organically under market stress: when the pay-fixed leg is dominant (many open pay-fixed swaps) and liquidity providers reduce their position, causing `liquidityPoolBalance` to decrease. This is precisely the scenario in which users most urgently need to exit.

---

## Vulnerable Code

**File:** `contracts/amm/spread/CalculateTimeWeightedNotionalLibs.sol:13-23`

```solidity
function calculateLpDepth(
    uint256 liquidityPoolBalance,
    uint256 totalCollateralPayFixed,
    uint256 totalCollateralReceiveFixed
) internal pure returns (uint256 lpDepth) {
    if (totalCollateralPayFixed >= totalCollateralReceiveFixed) {
        // VULNERABILITY: no unchecked block
        // REVERTS with Panic(0x11) when:
        // liquidityPoolBalance + totalCollateralReceiveFixed < totalCollateralPayFixed
        lpDepth = liquidityPoolBalance + totalCollateralReceiveFixed - totalCollateralPayFixed;
    } else {
        // REVERTS with Panic(0x11) when:
        // liquidityPoolBalance + totalCollateralPayFixed < totalCollateralReceiveFixed
        lpDepth = liquidityPoolBalance + totalCollateralPayFixed - totalCollateralReceiveFixed;
    }
}
```

**Trigger condition (pay-fixed dominant leg):**
```
liquidityPoolBalance + totalCollateralReceiveFixed < totalCollateralPayFixed
```

**Example with concrete values:**
```
liquidityPoolBalance      = 500e18
totalCollateralReceiveFixed = 50e18
totalCollateralPayFixed   = 600e18

Solidity 0.8 evaluates: 500e18 + 50e18 - 600e18
                       = 550e18 - 600e18
                       → Panic(0x11) arithmetic underflow → REVERT
```

---

## Complete Call Traces

### Call Path A — Opening New Swaps (BLOCKED)

```
User → IporProtocolRouter.openSwapPayFixed28daysUsdt(...)
  → AmmOpenSwapService.openSwapPayFixed28daysUsdt(...)
    → AmmOpenSwapServiceBaseV1._openSwapPayFixed(...)
        balance = IAmmStorageBaseV1(ammStorage).getBalancesForOpenSwap()
        // reads live on-chain state:
        // balance.totalCollateralPayFixed  ← _balances.totalCollateralPayFixed
        // balance.totalCollateralReceiveFixed ← _balances.totalCollateralReceiveFixed  
        // liquidityPoolBalance             ← _balances.liquidityPool
      → SpreadRouter.fallback()
        → getRouterImplementation(calculateAndUpdateOfferedRatePayFixed28Days.selector)
          // _onlyIporProtocolRouter() checked ✓
          → delegatecall to _spread28Days (Spread28Days)
        → Spread28Days.calculateAndUpdateOfferedRatePayFixed28Days(spreadInputs)
          → _calculateDemandPayFixedAndUpdateTimeWeightedNotional28Day(spreadInputs)
            → DemandSpreadLibs.calculatePayFixedSpread(inputData)
              → CalculateTimeWeightedNotionalLibs.calculateLpDepth(
                    inputData.liquidityPoolBalance,      // live balance
                    inputData.totalCollateralPayFixed,   // live balance
                    inputData.totalCollateralReceiveFixed // live balance
                )
              ← PANIC(0x11): REVERT ← all new swap openings blocked
```

**Source references:**
- `AmmOpenSwapServiceBaseV1.sol:140-165` — `getBalancesForOpenSwap()` → `SpreadInputs` construction
- `Spread28Days.sol:87-93` — `_getSpreadConfigForDemand` copies inputs unchanged
- `DemandSpreadLibs.sol:62-64` — calls `calculateLpDepth`
- `CalculateTimeWeightedNotionalLibs.sol:19` — underflow

---

### Call Path B — Early Closure with Unwind (BLOCKED)

```
User → IporProtocolRouter.closeSwapPayFixed28daysUsdt(swapId, ...)
  → AmmCloseSwapServiceUsdt._closeSwapPayFixed(...)
    → _preparePnlValueStructForClose(PAY_FIXED, ...)
      → SwapCloseLogicLibBaseV1.getClosableStatusForSwap(...)
        // When: absPnl < minLiquidationThreshold AND closeTime < swapEndTime
        // AND block.timestamp - openTimestamp > timeAfterOpenAllowedToCloseSwapWithUnwinding (1 day)
        ← returns (SWAP_IS_CLOSABLE, swapUnwindRequired=true)
      
      // swapUnwindRequired == true → enters unwind branch
      → SwapCloseLogicLib.calculateSwapUnwindWhenUnwindRequired(unwindParams)
        → calculateSwapUnwindPnlValueNormalized(unwindParams, direction=1, oppositeRiskIndicators)
          → RiskManagementLogic.calculateOfferedRate(
                direction=RECEIVE_FIXED,
                tenor=DAYS_28,
                swapNotional,
                SpreadOfferedRateContext{ asset, ammStorage, spreadRouter, ... },
                oppositeRiskIndicators
            )
            // Reads LIVE on-chain balances:
            balance = IAmmStorage(ammStorage).getBalancesForOpenSwap()
            // Calls Lens (no auth required):
            → spreadRouter.functionStaticCall(
                  ISpread28DaysLens.calculateOfferedRatePayFixed28Days.selector,
                  asset,
                  swapNotional,
                  demandSpreadFactor,
                  baseSpreadPerLeg,
                  balance.totalCollateralPayFixed,    // live state
                  balance.totalCollateralReceiveFixed, // live state
                  balance.liquidityPool,              // live state
                  indexValue,
                  fixedRateCapPerLeg
              )
              → SpreadRouter.getRouterImplementation(calculateOfferedRatePayFixed28Days.selector)
                // NO _onlyIporProtocolRouter() check for Lens functions
                → delegatecall to _spread28Days
              → Spread28Days.calculateOfferedRatePayFixed28Days(spreadInputs)
                → DemandSpreadLibs.calculatePayFixedSpread(inputData)
                  → CalculateTimeWeightedNotionalLibs.calculateLpDepth(
                        balance.liquidityPool,           // live state
                        balance.totalCollateralPayFixed,  // live state  
                        balance.totalCollateralReceiveFixed // live state
                    )
                  ← PANIC(0x11): REVERT ← early closure blocked
```

**Source references:**
- `AmmCloseSwapServiceStable.sol:205,455-462` — `_preparePnlValueStructForClose` → unwind branch
- `SwapCloseLogicLib.sol:20-80` — `calculateSwapUnwindWhenUnwindRequired`
- `SwapCloseLogicLib.sol:88-110` — `calculateSwapUnwindPnlValueNormalized`
- `RiskManagementLogic.sol:36-65` — `calculateOfferedRate` with live `getBalancesForOpenSwap()`
- `SpreadRouter.sol:97-103` — Lens selector returns without `_onlyIporProtocolRouter()`

---

## Proof of Concept (Foundry — Mainnet Fork)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../contracts/amm/spread/ISpread28DaysLens.sol";
import "../../contracts/amm/spread/ISpread60DaysLens.sol";
import "../../contracts/amm/spread/ISpread90DaysLens.sol";
import "../../contracts/interfaces/types/IporTypes.sol";

contract PoC_LpDepthUnderflow is Test {
    address constant USDT         = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant SPREAD_ROUTER = 0xAc1C86CEacf03d5AFC8b08A22fc38Ec7c72338ed;

    function setUp() public {
        vm.createSelectFork(vm.envString("ETHEREUM_PROVIDER_URL"));
    }

    /// @notice Reference: normal inputs succeed
    function test_Reference_NormalInputs_Succeed() public view {
        IporTypes.SpreadInputs memory inputs = IporTypes.SpreadInputs({
            asset: USDT,
            swapNotional: 0,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:     100_000e18,
            totalCollateralReceiveFixed:  50_000e18,
            liquidityPoolBalance:       1_000_000e18, // LP >> gap → OK
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16
        });
        // lpDepth = 1_000_000 + 50_000 - 100_000 = 950_000 > 0 → no revert
        uint256 rate = ISpread28DaysLens(SPREAD_ROUTER).calculateOfferedRatePayFixed28Days(inputs);
        assertTrue(rate >= 0);
    }

    /// @notice PoC #1A: pay-fixed dominant leg triggers Panic(0x11) underflow
    /// Condition: 500e18 + 50e18 - 600e18 = -50e18 → REVERT
    function test_PoC1A_Underflow_PayFixed_DoS() public {
        IporTypes.SpreadInputs memory inputs = IporTypes.SpreadInputs({
            asset: USDT,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:    600e18,  // dominant leg
            totalCollateralReceiveFixed: 50e18,
            liquidityPoolBalance:       500e18,  // 500 + 50 < 600 → UNDERFLOW
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16
        });

        vm.expectRevert();
        ISpread28DaysLens(SPREAD_ROUTER).calculateOfferedRatePayFixed28Days(inputs);
    }

    /// @notice PoC #1B: receive-fixed dominant leg — same bug, opposite side
    function test_PoC1B_Underflow_ReceiveFixed_DoS() public {
        IporTypes.SpreadInputs memory inputs = IporTypes.SpreadInputs({
            asset: USDT,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:     50e18,
            totalCollateralReceiveFixed: 600e18, // dominant leg
            liquidityPoolBalance:        500e18,  // 500 + 50 < 600 → UNDERFLOW
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16
        });

        vm.expectRevert();
        ISpread28DaysLens(SPREAD_ROUTER).calculateOfferedRateReceiveFixed28Days(inputs);
    }

    /// @notice PoC #1C: all tenors are affected (28 / 60 / 90 days)
    function test_PoC1C_AllTenors_DoS() public {
        IporTypes.SpreadInputs memory inputs = IporTypes.SpreadInputs({
            asset: USDT,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:    600e18,
            totalCollateralReceiveFixed: 50e18,
            liquidityPoolBalance:       500e18,
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16
        });

        vm.expectRevert(); ISpread28DaysLens(SPREAD_ROUTER).calculateOfferedRatePayFixed28Days(inputs);
        vm.expectRevert(); ISpread60DaysLens(SPREAD_ROUTER).calculateOfferedRatePayFixed60Days(inputs);
        vm.expectRevert(); ISpread90DaysLens(SPREAD_ROUTER).calculateOfferedRatePayFixed90Days(inputs);
    }
}
```

**Run command:**
```bash
forge test --fork-url $ETHEREUM_PROVIDER_URL \
           --match-path test/fork/PoC_BugBounty.t.sol \
           --match-test "test_PoC1" \
           -vvvv
```

**Expected output:** All three `test_PoC1*` tests PASS with the expected `vm.expectRevert()` intercepting the underflow revert. `test_Reference_NormalInputs_Succeed` also PASSES.

---

## Impact

### Primary Impact — Existing Positions Cannot Exit Early

When the market condition is met, users holding active swaps who attempt early closure via the unwind mechanism receive a revert. Their **collateral remains locked** for the remaining swap duration:

- 28-day swap: up to **27 days** locked
- 60-day swap: up to **59 days** locked  
- 90-day swap: up to **89 days** locked

During this period, if the user is in a losing position, losses accumulate with no means of exit. Closing at maturity remains functional, but the user is unable to cut losses early.

**The condition is most likely to occur precisely when users are most motivated to exit:** a market stress event with heavy pay-fixed exposure and LP withdrawals. This is the classic scenario for a "bank run" on the spread mechanism — the bug triggers at the worst possible time.

### Secondary Impact — All New Swap Openings Blocked

While the market condition persists, no new swaps can be opened on any asset (USDT, USDC, DAI) in any direction (pay-fixed or receive-fixed) for any tenor. This is a complete halt of the protocol's core function.

### Scope of Affected Assets

The bug exists in **two independent libraries**, each affecting different pools:

| Library | Affected Assets |
|---------|----------------|
| `contracts/amm/spread/CalculateTimeWeightedNotionalLibs.sol:19` | DAI, USDC, USDT (stable pools) |
| `contracts/base/spread/CalculateTimeWeightedNotionalLibsBaseV1.sol:19` | stETH, weETH (BaseV1 pools) |

---

## Root Cause

Solidity 0.8.x enables checked arithmetic by default. The subtraction in `calculateLpDepth` lacks an `unchecked` block, meaning any arithmetic underflow results in a hard revert (`Panic(0x11)`) rather than wrapping or returning a sentinel value.

The function signature returns `uint256 lpDepth`, meaning a negative result is semantically invalid. The protocol's intent when `lpDepth` would be negative is likely to return `0` (pool fully imbalanced, no depth). The fix should handle this case explicitly rather than reverting.

---

## Recommended Fix

```solidity
function calculateLpDepth(
    uint256 liquidityPoolBalance,
    uint256 totalCollateralPayFixed,
    uint256 totalCollateralReceiveFixed
) internal pure returns (uint256 lpDepth) {
    if (totalCollateralPayFixed >= totalCollateralReceiveFixed) {
        uint256 netExposure = totalCollateralPayFixed - totalCollateralReceiveFixed;
        // Return 0 if LP cannot cover net exposure (pool fully imbalanced)
        lpDepth = liquidityPoolBalance >= netExposure
            ? liquidityPoolBalance - netExposure
            : 0;
    } else {
        uint256 netExposure = totalCollateralReceiveFixed - totalCollateralPayFixed;
        lpDepth = liquidityPoolBalance >= netExposure
            ? liquidityPoolBalance - netExposure
            : 0;
    }
}
```

**Why this fix is correct:** When `lpDepth = 0`, the demand spread reaches its maximum (`3e17` = 30%) as defined in `calculateSpreadFunction`. This is economically correct behavior — a fully imbalanced pool charges maximum spread to discourage further imbalance, rather than reverting and blocking all operations.

**Note:** The companion fix for `lpDepth = 0` causing division by zero in `calculateSpreadFunction` (when `notionalDepth = lpDepth * demandSpreadFactor = 0`) should be addressed simultaneously. See separate finding.

---

## Verification

All findings were verified directly in the source code without inference:

| Verification Point | Source |
|-------------------|--------|
| No `unchecked` block in `calculateLpDepth` | `CalculateTimeWeightedNotionalLibs.sol:13-23` (the only `unchecked` in file is `++i` at line 156 in a loop counter) |
| Lens functions have no access control | `SpreadRouter.sol:97-103` — no `_onlyIporProtocolRouter()` call |
| Open swap path reads live balances | `AmmOpenSwapServiceBaseV1.sol:140` — `getBalancesForOpenSwap()` |
| Close swap unwind path reads live balances | `RiskManagementLogic.sol:44` — `getBalancesForOpenSwap()` |
| `getBalancesForOpenSwap` returns live storage | `AmmStorage.sol:138-147` — direct `_balances.*` reads |
| `pragma solidity 0.8.26` (checked arithmetic) | `CalculateTimeWeightedNotionalLibs.sol:2` |
