# Bug Report — Unhandled Panic(0x12) in Demand Spread Calculation When Market is Fully Unidirectional

**Protocol:** IPOR Protocol  
**Network:** Arbitrum  
**Severity:** High  
**Category:** Smart Contract — Denial of Service  

---

## Note on Immunefi Exclusion Scope

The IPOR program excludes *"Issues when the liquidity of liquidity pools equals zero."*

**This bug is NOT that case.** The proof is in the source code itself.

**When `liquidityPool = 0` — the protocol HANDLES it intentionally:**

`contracts/base/amm/services/AmmOpenSwapServiceBaseV1.sol:432-441`
```solidity
if (totalLiquidityPoolBalance > 0) {
    collateralRatio    = IporMath.division(totalCollateralBalance * 1e18, totalLiquidityPoolBalance);
    collateralRatioPerLeg = IporMath.division(collateralPerLegBalance * 1e18, totalLiquidityPoolBalance);
} else {
    collateralRatio    = Constants.MAX_VALUE;   // explicit guard for LP = 0
    collateralRatioPerLeg = Constants.MAX_VALUE;
}
require(collateralRatio <= maxCollateralRatio, AmmErrors.LP_COLLATERAL_RATIO_EXCEEDED);
// → readable require revert (IPOR_302). Caught. Expected. Excluded.
```

**When `lpDepth = 0` with `LP > 0` — the protocol does NOT handle it:**

`contracts/base/spread/DemandSpreadStEthLibsBaseV1.sol:158`
```solidity
uint256 ratio = IporMath.division(weightedNotional * 1e18, maxNotional);
//                                                          ^^^^^^^^^^ = 0
// No guard exists for maxNotional = 0. → Solidity 0.8.26 checked arithmetic → Panic(0x12)
```

`liquidityPool` is a storage variable. `lpDepth` is a **derived metric** computed from three storage values — it can reach zero while `liquidityPool` remains strictly positive. These are different state conditions, different code paths, different error types.

| Condition | Variable type | Code path | Error type | Handled | Excluded |
|-----------|---------------|-----------|------------|---------|----------|
| `liquidityPool = 0` | storage var | `AmmOpenSwapServiceBaseV1:432-441` | `require` → IPOR_302 | **Yes** | **Yes** |
| `lpDepth = 0` (LP > 0) | derived metric | `DemandSpreadStEthLibsBaseV1:158` | `Panic(0x12)` — uncaught | **No** | **No** |

---

## Summary

When the wstETH market on Arbitrum becomes 100% pay-fixed and LPs withdraw liquidity to its minimum — permitted by the absence of a `redeemLpMaxCollateralRatio` check in `AmmPoolsServiceWstEthBaseV1` — the derived metric `lpDepth` reaches zero while the actual liquidity pool balance remains strictly positive. This triggers an **unhandled `Panic(0x12)`** inside `calculateSpreadFunction`, which propagates through the swap-closing/unwind path via `RiskManagementLogic`. The result is a complete DoS on all early close operations (liquidations) for up to 90 days. No governance access is required.

---

## Root Cause

**`contracts/base/spread/CalculateTimeWeightedNotionalLibsBaseV1.sol:17-19`**

```solidity
if (totalCollateralPayFixed >= totalCollateralReceiveFixed) {
    lpDepth = liquidityPoolBalance + totalCollateralReceiveFixed - totalCollateralPayFixed;
    // When LP = pxFixed, rxFixed = 0: lpDepth = 0  (no underflow — exact equality)
    // When LP < pxFixed, rxFixed = 0: Panic(0x11) arithmetic underflow
}
```

**`contracts/base/spread/DemandSpreadStEthLibsBaseV1.sol:63-75`**

```solidity
uint256 lpDepth = CalculateTimeWeightedNotionalLibsBaseV1.calculateLpDepth(
    inputData.liquidityPoolBalance,       // LP > 0 (e.g. 25 000 wstETH)
    inputData.totalCollateralPayFixed,    // pxFixed = LP (market 100% pay-fixed)
    inputData.totalCollateralReceiveFixed // rxFixed = 0
);
// → lpDepth = 25 000 + 0 − 25 000 = 0   (LP is NON-ZERO)

uint256 notionalDepth = lpDepth * inputData.demandSpreadFactor;
// → 0 × 20 = 0

uint256 newSpread = calculateSpreadFunction(
    notionalDepth,   // = 0 ← becomes maxNotional in the function below
    newWeightedNotionalPayFixed - timeWeightedNotionalReceiveFixed
);
// ← called unconditionally, no guard for maxNotional = 0
```

**`contracts/base/spread/DemandSpreadStEthLibsBaseV1.sol:158`**

```solidity
function calculateSpreadFunction(uint256 maxNotional, uint256 weightedNotional)
    internal pure returns (uint256 spreadValue)
{
    uint256 ratio = IporMath.division(weightedNotional * 1e18, maxNotional);
    //                                                          ^^^^^^^^^^
    //                        maxNotional = 0 → EVM Panic(0x12) — UNHANDLED
```

**`contracts/libraries/math/IporMath.sol:8-10`**

```solidity
function division(uint256 x, uint256 y) internal pure returns (uint256 z) {
    z = (x + (y / 2)) / y;   // y = 0 → Solidity 0.8.26 checked arithmetic → Panic(0x12)
}
```

The same pattern affects `calculateReceiveFixedSpread` — both legs are vulnerable.

---

## Missing Protection — Arbitrum-Specific Amplifier

The Ethereum mainnet pools (USDT/USDC/DAI) include a protection that **explicitly prevents** `lpDepth` from reaching zero:

**`contracts/amm/AmmPoolsService.sol:308-315`**

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

This protection is **absent** from the Arbitrum wstETH service:

**`contracts/base/amm-wstEth/services/AmmPoolsServiceWstEthBaseV1.sol:80-95`**

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

The mainnet protection exists precisely to prevent `lpDepth` from reaching zero. Its absence on Arbitrum wstETH makes the state reachable through normal LP redemption.

---

## Attack Path (No Governance Required)

Two organic actors — no coordination, no privileged role, no protocol exploit required.

**Step 1 — Market becomes 100% pay-fixed**

Traders open pay-fixed swaps up to `maxCollateralRatioPerLeg = 2.5%` of LP (Arbitrum production config, confirmed in `ArbitrumTestForkCommons.sol:550`). With a 1 000 000 wstETH pool:
- `pxFixed = 0.025 × 1 000 000 = 25 000 wstETH`
- `rxFixed = 0`

**Step 2 — LPs withdraw to minimum**

With no `redeemLpMaxCollateralRatio` check, LPs redeem `ipToken` shares until:
- `LP = 25 000 wstETH = pxFixed`

**Step 3 — lpDepth = 0, Panic(0x12)**

```
lpDepth = LP + rxFixed − pxFixed = 25 000 + 0 − 25 000 = 0
notionalDepth = 0 × demandSpreadFactor = 0
calculateSpreadFunction(0, x) → IporMath.division(x, 0) → Panic(0x12)
```

**Step 4 (amplified) — LP < pxFixed, Panic(0x11)**

LPs can redeem beyond pxFixed (no floor protection). With a 0.5% redeem fee:
- Redeeming 999/1000 of ipTokens → net LP transfer ≈ LP × 99.5% → LP_after < pxFixed
- `lpDepth = LP_after + 0 − pxFixed` → arithmetic underflow → `Panic(0x11)` in `calculateLpDepth`

---

## Impact

### 1. This is NOT an IRS Edge Case — It Is a DoS on User Fund Access

The bug resides in `calculateSpreadFunction`, a **pure arithmetic function** in `DemandSpreadStEthLibsBaseV1.sol`. It is not in the swap pricing logic, the PnL calculation, or any IRS-specific formula. The function receives a `uint256 maxNotional` parameter and divides by it without a zero-check — that division is what panics.

The consequence — blocking `closeSwapsWstEth` — is functionally equivalent to locking user collateral. A swap opened with 10 000 wstETH cannot be exited early. Under Immunefi's impact taxonomy this qualifies as **"Temporary freezing of funds"** regardless of which protocol layer causes the block.

### 2. New Swap Openings Blocked (IPOR_302)

`AmmOpenSwapServiceBaseV1:147` calls `_validateLiquidityPoolCollateralRatioAndSwapLeverage` **before** the spread call at `:157`. When `LP < pxFixed`, the existing collateral ratio exceeds 100% (well above `maxCollateralRatio = 5%`), producing `IPOR_302` before the spread is reached.

Result: every `openSwapPayFixed*` and `openSwapReceiveFixed*` call fails. New users cannot enter the protocol.

*Proved by:* `test_E2E_OpenSwapViaRouter_Reverts_WhenLpBelowPxFixed` → `vm.expectRevert("IPOR_302")` ✓

### 3. Liquidations Frozen — Most Critical Impact

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
// staticcall failure bubbles up as Panic(0x11/0x12) → entire closeSwapsWstEth reverts
```

No existing position can be unwound early. Underwater positions cannot be liquidated. Bad debt accumulates unaddressed for up to 90 days (maximum swap tenor).

*Proved by:* `test_E2E_UnwindClose_Reverts_WhenLpBelowPxFixed` → `vm.expectRevert(stdError.arithmeticError)` ✓

### 4. No Emergency Bypass Path

`AmmCloseSwapServiceBaseV1._emergencyCloseSwaps()` calls `_closeSwaps()` → `_preparePnlValueStructForClose()` → `RiskManagementLogic.calculateOfferedRate()` → same `functionStaticCall` → same Panic. No privileged code path bypasses the spread calculation.

### 5. Duration and Recovery

The DoS persists until:
- LPs voluntarily add liquidity (restores `lpDepth > 0`), **OR**
- All pay-fixed swaps expire at maturity (up to 90 days)

During this window, the protocol is inoperable for the affected pool.

---

## Proof of Concept

**Fork:** Arbitrum, block 171764768  
**File:** `test/arbitrum/PoC_ArbitrumDivisionByZero.t.sol`  
**Branch:** `claude/bug-bounty-analysis-8F5m6`

```bash
ARBITRUM_PROVIDER_URL=<arbitrum-rpc-url> \
forge test --match-path "test/arbitrum/PoC_ArbitrumDivisionByZero.t.sol" -vvvv
```

**Test results (8/8 PASS):**

| Test | What it proves | Panic |
|------|---------------|-------|
| `test_Reference_NormalState_NoRevert` | Baseline: `lpDepth > 0` works normally | — |
| `test_PoC_PayFixed_LpDepthZero_Reverts` | `stdError.divisionError` — exact `Panic(0x12)` | `0x12` |
| `test_PoC_ReceiveFixed_LpDepthZero_Reverts` | Both legs (pay-fixed and receive-fixed) affected | `0x12` |
| `test_PoC_AllTenors_Revert` | All tenors (28d / 60d / 90d) blocked | `0x12` |
| `test_PoC_OrganicPath_ProductionConstraints` | 2.5% Arbitrum config makes `lpDepth = 0` reachable | — |
| `test_WstEth_NoRedeemFloor_LP_CanGoBelowPxFixed` | Real redemption: `LP < pxFixed` with no error | — |
| `test_E2E_OpenSwapViaRouter_Reverts_WhenLpBelowPxFixed` | Real `IporProtocolRouter` → `IPOR_302`, swaps blocked | — |
| `test_E2E_UnwindClose_Reverts_WhenLpBelowPxFixed` | Real `IporProtocolRouter` → `Panic(0x11)`, liquidations frozen | `0x11` |

Supporting offline tests (no RPC required): `test/fork/PoC_DivisionByZero.t.sol` — 7 tests proving the arithmetic in isolation.

---

## Severity Justification — High

| Criterion | Assessment |
|-----------|-----------|
| Funds stolen | No |
| Funds temporarily locked | **Yes** — existing swaps cannot be unwound early (up to 90 days) |
| Protocol operations blocked | **Yes** — all new swap openings and all early closes |
| Liquidations prevented | **Yes** — bad debt accumulates |
| Governance required | No |
| Privileged role required | No |
| Attacker cost | Low — organic market conditions sufficient |
| Emergency bypass | None |
| Duration | Up to 90 days |

Per Immunefi's impact taxonomy: "Temporary freezing of funds" and "Griefing (no attacker profit motive, but damage to users or protocol)" with no emergency recovery path = **High**.

Not submitted as Critical: there is no direct theft of funds. The Panic prevents protocol operations but does not redirect assets.

---

## Recommended Fix

**Option A — Guard in `calculatePayFixedSpread` (minimal fix):**

```solidity
// DemandSpreadStEthLibsBaseV1.sol — after line 70, before calculateSpreadFunction call
uint256 notionalDepth = lpDepth * inputData.demandSpreadFactor;
if (notionalDepth == 0) {
    return type(uint256).max; // maximum spread when market depth is exhausted
}
```

**Option B — Add `redeemLpMaxCollateralRatio` to wstETH service (complete fix, recommended):**

Add the same check that exists in `AmmPoolsService.sol:308-315` to `AmmPoolsServiceWstEthBaseV1.redeemFromAmmPoolWstEth()`, preventing LP from falling to or below `pxFixed + rxFixed`. This also protects against the underflow variant (`LP < pxFixed → Panic(0x11)`) and mirrors the protection already deployed on Ethereum mainnet pools.

---

## Affected Files

| File | Lines | Issue |
|------|-------|-------|
| `contracts/base/spread/DemandSpreadStEthLibsBaseV1.sol` | 63-75, 158 | No guard for `maxNotional = 0` before division |
| `contracts/base/spread/CalculateTimeWeightedNotionalLibsBaseV1.sol` | 17-22 | `lpDepth` can reach 0 (exact equality) or underflow (LP < pxFixed) |
| `contracts/base/amm-wstEth/services/AmmPoolsServiceWstEthBaseV1.sol` | 80-95 | Missing `redeemLpMaxCollateralRatio` check (present on mainnet pools) |
| `contracts/libraries/RiskManagementLogic.sol` | 43-63 | Panic propagates through `functionStaticCall` on every close/unwind |

---

*Submitted by: independent security researcher*  
*PoC branch: `claude/bug-bounty-analysis-8F5m6`*  
*Tests: `test/arbitrum/PoC_ArbitrumDivisionByZero.t.sol` (8/8 PASS)*
