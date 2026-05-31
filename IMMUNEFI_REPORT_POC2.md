# Bug Report — Unhandled Panic(0x12) in Demand Spread Calculation When Market is Fully Unidirectional

**Protocol:** IPOR Protocol  
**Network:** Arbitrum  
**Severity:** High  
**Category:** Smart Contract — Denial of Service  

---

## Summary

When the wstETH market on Arbitrum becomes 100% pay-fixed (all open positions are pay-fixed, none receive-fixed), and LPs withdraw liquidity to its minimum value — which is permitted by the absence of a `redeemLpMaxCollateralRatio` check in `AmmPoolsServiceWstEthBaseV1` — the derived metric `lpDepth` reaches zero while the actual liquidity pool balance remains strictly positive.

This triggers an **unhandled `Panic(0x12)` (EVM division by zero)** inside `calculateSpreadFunction`, which propagates through both the swap-opening path and the swap-closing/unwind path via `RiskManagementLogic`. The result is a complete DoS on all new swap openings and on all early close operations (liquidations) for the duration of the vulnerable state — up to 90 days.

No governance access is required. The state is reachable through two organic actors: traders who fill the pay-fixed side, and LPs who withdraw their liquidity.

---

## Note on Immunefi Exclusion Scope

The IPOR program excludes *"Issues when the liquidity of liquidity pools equals zero."*

**This report does NOT cover that excluded case.** The distinction is proven in the source code:

When `liquidityPool = 0`, the protocol handles it **intentionally and gracefully** at `AmmOpenSwapServiceBaseV1.sol:432-441`:

```solidity
if (totalLiquidityPoolBalance > 0) {
    collateralRatio    = IporMath.division(totalCollateralBalance * 1e18, totalLiquidityPoolBalance);
    collateralRatioPerLeg = IporMath.division(collateralPerLegBalance * 1e18, totalLiquidityPoolBalance);
} else {
    collateralRatio    = Constants.MAX_VALUE;   // explicit guard for LP=0
    collateralRatioPerLeg = Constants.MAX_VALUE;
}
require(collateralRatio <= maxCollateralRatio, AmmErrors.LP_COLLATERAL_RATIO_EXCEEDED);
```

→ LP=0 produces a **readable `require` revert**. It is a known, handled edge case.

This report covers the case where **`liquidityPool > 0`** (e.g., 25,000 wstETH remain in the pool) but the **derived metric `lpDepth = 0`** due to market imbalance. There is **no guard** before `calculateSpreadFunction`, producing an **unhandled `Panic(0x12)`**.

| Condition | Code path | Error type | Handled? | Excluded? |
|-----------|-----------|------------|----------|-----------|
| `liquidityPool = 0` | `_validateLiquidityPool` (line 432-441) | `require` — `LP_COLLATERAL_RATIO_EXCEEDED` | **Yes** | **Yes** |
| `lpDepth = 0` with LP > 0 | `calculateSpreadFunction` (line 158) | `Panic(0x12)` — unhandled | **No** | **No** |

---

## Root Cause

**File: `contracts/base/spread/DemandSpreadStEthLibsBaseV1.sol`**

```solidity
// Line 63-67
uint256 lpDepth = CalculateTimeWeightedNotionalLibsBaseV1.calculateLpDepth(
    inputData.liquidityPoolBalance,       // LP > 0 (e.g., 25,000 wstETH)
    inputData.totalCollateralPayFixed,    // pxFixed = LP (market fully pay-fixed)
    inputData.totalCollateralReceiveFixed // rxFixed = 0
);
// → lpDepth = LP + 0 - LP = 0   (LP is NON-ZERO)

// Line 70
uint256 notionalDepth = lpDepth * inputData.demandSpreadFactor;
// → 0 * 20 = 0

// Line 72-75 — called unconditionally, no guard for maxNotional=0
uint256 newSpread = calculateSpreadFunction(
    notionalDepth,                              // = 0
    newWeightedNotionalPayFixed - timeWeightedNotionalReceiveFixed
);
```

**File: `contracts/base/spread/DemandSpreadStEthLibsBaseV1.sol:158`**

```solidity
function calculateSpreadFunction(uint256 maxNotional, uint256 weightedNotional)
    internal pure returns (uint256 spreadValue)
{
    uint256 ratio = IporMath.division(weightedNotional * 1e18, maxNotional);
    //                                                          ^^^^^^^^^^
    //                                  maxNotional = 0 → EVM Panic(0x12) — UNHANDLED
```

**File: `contracts/libraries/math/IporMath.sol:8-10`**

```solidity
function division(uint256 x, uint256 y) internal pure returns (uint256 z) {
    z = (x + (y / 2)) / y;   // y = 0 → Solidity 0.8.26 checked arithmetic → Panic(0x12)
}
```

**File: `contracts/base/spread/CalculateTimeWeightedNotionalLibsBaseV1.sol:17-19`**

```solidity
if (totalCollateralPayFixed >= totalCollateralReceiveFixed) {
    lpDepth = liquidityPoolBalance + totalCollateralReceiveFixed - totalCollateralPayFixed;
    // When LP = pxFixed, rxFixed = 0: lpDepth = 0 (no underflow — exact equality)
    // When LP < pxFixed, rxFixed = 0: Panic(0x11) arithmetic underflow
}
```

---

## Missing Protection — Arbitrum-Specific Amplifier

The Ethereum mainnet pools (USDT/USDC/DAI) include a protection that **explicitly prevents** `lpDepth` from reaching zero:

**File: `contracts/amm/AmmPoolsService.sol:308-315`**

```solidity
require(
    _calculateRedeemedCollateralRatio(
        balance.liquidityPool,
        balance.totalCollateralPayFixed + balance.totalCollateralReceiveFixed,
        redeemAmountStruct.wadRedeemAmount
    ) <= poolCfg.redeemLpMaxCollateralRatio,   // = 1e18 (100%)
    AmmPoolsErrors.REDEEM_LP_COLLATERAL_RATIO_EXCEEDED
);
// → floors LP at pxFixed + rxFixed → lpDepth ≥ 0 always
```

This protection is **completely absent** from the Arbitrum wstETH service:

**File: `contracts/base/amm-wstEth/services/AmmPoolsServiceWstEthBaseV1.sol:80-95`**

```solidity
function redeemFromAmmPoolWstEth(address beneficiary, uint256 ipTokenAmount) external {
    require(
        ipTokenAmount > 0 && ipTokenAmount <= IIpToken(ipwstEth).balanceOf(msg.sender),
        AmmPoolsErrors.CANNOT_REDEEM_IP_TOKEN_TOO_LOW
    );
    // NO redeemLpMaxCollateralRatio check
    // Only constraint: require(amountToRedeem > 0, ...)
    // → LPs can withdraw until LP = pxFixed (lpDepth = 0) or LP < pxFixed (underflow)
```

The mainnet protection exists precisely to prevent `lpDepth` from reaching 0. Its absence on Arbitrum wstETH makes the vulnerability fully exploitable with no protocol-level resistance.

---

## Attack Path (No Governance Required)

**Step 1 — Market becomes 100% pay-fixed**

Traders open pay-fixed swaps up to `maxCollateralRatioPerLeg = 2.5%` of LP (Arbitrum production config, confirmed in test infrastructure). With a 1,000,000 wstETH pool:
- `pxFixed = 0.025 × 1,000,000 = 25,000 wstETH`
- `rxFixed = 0`

This is organic market behavior — no coordination or attack required.

**Step 2 — LPs withdraw to minimum**

With no `redeemLpMaxCollateralRatio` check, LPs redeem `ipToken` shares until:
- `LP = 25,000 wstETH = pxFixed`

**Step 3 — lpDepth = 0**

```
lpDepth = LP + rxFixed - pxFixed = 25,000 + 0 - 25,000 = 0
notionalDepth = 0 × demandSpreadFactor = 0
calculateSpreadFunction(0, x) → IporMath.division(x, 0) → Panic(0x12)
```

**Step 4 — Amplified: LP < pxFixed (underflow)**

LPs can redeem beyond pxFixed (no floor protection). With a 0.5% redeem fee:
- Redeeming 999/1000 of ipTokens → net transfer ≈ LP × 99.5% → LP_after < pxFixed
- `lpDepth = LP_after + 0 - pxFixed` → arithmetic underflow → `Panic(0x11)`

Both panic variants (0x11 and 0x12) are triggered from the same missing guard.

---

## Impact

### 1. All New Swap Openings Blocked

`AmmOpenSwapServiceBaseV1.sol:157` passes live balances to the spread contract:

```solidity
uint256 offeredRateValue = ISpreadBaseV1(spread).calculateAndUpdateOfferedRatePayFixed(
    ISpreadBaseV1.SpreadInputs({
        totalCollateralPayFixed:    balance.totalCollateralPayFixed,   // live
        totalCollateralReceiveFixed: balance.totalCollateralReceiveFixed, // live
        liquidityPoolBalance:       liquidityPoolBalance,               // live
        ...
    })
);
```

When live balances give `lpDepth ≤ 0`, `calculateAndUpdateOfferedRatePayFixed` reverts. Every `openSwapPayFixed*` and `openSwapReceiveFixed*` call fails.

### 2. Liquidations Frozen — Bad Debt Accumulates

`RiskManagementLogic.sol:43-63` fetches **live balances** during every swap close/unwind:

```solidity
IporTypes.AmmBalancesForOpenSwapMemory memory balance =
    IAmmStorage(spreadOfferedRateCtx.ammStorage).getBalancesForOpenSwap();
// Live balances → lpDepth = 0 → spread staticcall reverts

return abi.decode(
    spreadOfferedRateCtx.spreadRouter.functionStaticCall(
        abi.encodeWithSelector(determineSpreadMethodSig(direction, tenor), ...)
    ),
    (uint256)
);
// staticcall reverts → entire closeSwapsWstEth transaction reverts
```

Result: **No open position can be closed early** (unwind). Underwater positions cannot be liquidated. Bad debt accumulates for up to 90 days (maximum swap tenor).

### 3. No Emergency Bypass Path

`AmmCloseSwapServiceBaseV1._emergencyCloseSwaps()` calls `_closeSwaps()` → same `_preparePnlValueStructForClose()` → same `RiskManagementLogic.calculateOfferedRate()` → same revert. There is no privileged bypass.

### 4. Duration

The DoS persists until:
- LPs voluntarily add liquidity (restores lpDepth > 0), **OR**
- All pay-fixed swaps expire at maturity (up to 90 days)

During this window, the protocol is inoperable for the affected pool.

---

## Proof of Concept

### PoC File: `test/arbitrum/PoC_ArbitrumDivisionByZero.t.sol`

Fork: Arbitrum, block 171764768  
RPC: `ARBITRUM_PROVIDER_URL=<arbitrum-rpc-url>`  

```bash
forge test --match-path "test/arbitrum/PoC_ArbitrumDivisionByZero.t.sol" -vvvv
```

**Test results (8 PASS):**

| Test | Proof | Panic |
|------|-------|-------|
| `test_Reference_NormalState_NoRevert` | Baseline: normal lpDepth > 0 works | — |
| `test_PoC_PayFixed_LpDepthZero_Reverts` | `stdError.divisionError` exact Panic(0x12) | `0x12` |
| `test_PoC_ReceiveFixed_LpDepthZero_Reverts` | Both directions affected | `0x12` |
| `test_PoC_AllTenors_Revert` | All tenors (28d/60d/90d) blocked | `0x12` |
| `test_PoC_OrganicPath_ProductionConstraints` | 2.5% Arbitrum config permits lpDepth=0 | — |
| `test_WstEth_NoRedeemFloor_LP_CanGoBelowPxFixed` | LP < pxFixed via real redemption | — |
| `test_E2E_OpenSwapViaRouter_Reverts_WhenLpBelowPxFixed` | Real IporProtocolRouter → Panic(0x11) | `0x11` |
| `test_E2E_UnwindClose_Reverts_WhenLpBelowPxFixed` | Liquidations frozen → Panic(0x11) | `0x11` |

### Supporting Unit Tests: `test/fork/PoC_DivisionByZero.t.sol`

No RPC required. Proves the arithmetic in isolation (7 tests, all PASS confirmed):

```bash
forge test --match-path "test/fork/PoC_DivisionByZero.t.sol" --offline -vvvv
```

---

## Severity Justification — High

| Criterion | Assessment |
|-----------|-----------|
| Funds stolen | No |
| Funds temporarily locked | Yes — existing swaps cannot be unwound early |
| Protocol operations blocked | Yes — all swap openings and early closes |
| Liquidations prevented | **Yes** — underwater positions accumulate bad debt |
| Governance required | No |
| Attacker cost | Low — organic market conditions |
| Duration | Up to 90 days |
| Emergency bypass | None |

Per Immunefi's impact taxonomy, "Griefing (e.g., no attacker profit motive, but damage to the users or the protocol)" and "Temporary freezing of funds" with no emergency recovery path qualify as **High**.

---

## Recommended Fix

**Option A — Guard in `calculatePayFixedSpread` (minimal fix):**

```solidity
// DemandSpreadStEthLibsBaseV1.sol
uint256 notionalDepth = lpDepth * inputData.demandSpreadFactor;
if (notionalDepth == 0) {
    return type(uint256).max; // maximum spread when depth is exhausted
}
```

**Option B — Add `redeemLpMaxCollateralRatio` to wstETH service (protective fix):**

Add the same check that exists in `AmmPoolsService.sol:308-315` to `AmmPoolsServiceWstEthBaseV1.redeemFromAmmPoolWstEth()`, preventing LP from falling to or below `pxFixed + rxFixed`.

**Option B is the more complete fix** as it also protects against the underflow case (LP < pxFixed → Panic 0x11) and mirrors the existing protection on mainnet pools.

---

## Affected Files

| File | Lines | Issue |
|------|-------|-------|
| `contracts/base/spread/DemandSpreadStEthLibsBaseV1.sol` | 63-75, 158 | No guard for `maxNotional=0` before division |
| `contracts/base/spread/CalculateTimeWeightedNotionalLibsBaseV1.sol` | 17-22 | `lpDepth` can reach 0 or underflow |
| `contracts/base/amm-wstEth/services/AmmPoolsServiceWstEthBaseV1.sol` | 80-110 | Missing `redeemLpMaxCollateralRatio` check |
| `contracts/libraries/RiskManagementLogic.sol` | 43-63 | Panic propagates through staticcall on close/unwind |

---

*Submitted by: independent security researcher*  
*PoC repository branch: `claude/bug-bounty-analysis-8F5m6`*
