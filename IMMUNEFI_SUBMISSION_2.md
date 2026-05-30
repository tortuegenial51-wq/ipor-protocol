# Immunefi Bug Bounty Submission #2 — IPOR Protocol

## Title

Missing `block.chainid` in RiskIndicators Signature Hash — Cross-Chain Signature Replay Attack

## Severity

**Medium** (EIP-712 Non-Compliance / Cross-Chain Signature Replay)

---

## Summary

The `RiskIndicatorsValidatorLib.hashRiskIndicatorsInputs()` function does not include `block.chainid` in the hash signed by the `messageSigner`. This violates EIP-712 best practices and enables cross-chain signature replay: a valid RiskIndicators signature from one IPOR chain deployment can be reused on another chain deployment if the asset address is identical on both chains.

---

## Vulnerability Details

### Affected File

**`contracts/libraries/RiskIndicatorsValidatorLib.sol`**, lines 31–52

```solidity
function hashRiskIndicatorsInputs(
    AmmTypes.RiskIndicatorsInputs memory inputs,
    address asset,
    uint256 tenor,
    uint256 direction
) private pure returns (bytes32) {
    return
        keccak256(
            abi.encodePacked(
                inputs.maxCollateralRatio,
                inputs.maxCollateralRatioPerLeg,
                inputs.maxLeveragePerLeg,
                inputs.baseSpreadPerLeg,
                inputs.fixedRateCapPerLeg,
                inputs.demandSpreadFactor,
                inputs.expiration,
                asset,          // ← differentiates assets, but NOT chains
                tenor,
                direction
                // ← block.chainid IS MISSING
            )
        );
}
```

### What's Missing

The EIP-712 standard mandates that domain separators include `chainId` to prevent cross-chain replay attacks. The `hashRiskIndicatorsInputs` function uses `asset` (an address) to partially differentiate chains, but this is insufficient if the same asset address exists on multiple chains.

### Verification

Confirmed by reading `contracts/libraries/RiskIndicatorsValidatorLib.sol:36–51`. The `keccak256` call contains no reference to `block.chainid`, `chainid`, or any chain-specific data.

---

## Impact Analysis

### When Is This Exploitable?

IPOR Protocol is deployed on **Ethereum mainnet (chainId=1)**, **Arbitrum (chainId=42161)**, and **Base (chainId=8453)**.

The replay attack is exploitable when an asset address is **identical** across two IPOR chain deployments.

#### Current Production Assessment

| Asset | Ethereum | Arbitrum | Base | Replay possible? |
|-------|----------|----------|------|-----------------|
| USDT | `0xdAC17F...` | `0xFd086b...` | bridged | **NO** (different addresses) |
| USDC | `0xA0b869...` | `0xFF970A...` | `0x833589...` | **NO** |
| DAI | `0x6B1754...` | `0xDA10009...` | `0x50c5...` | **NO** |
| stETH | `0xae7ab9...` | N/A | N/A | N/A |

In the **current production configuration**, the major stable assets have different addresses across chains, which limits the immediate exploit window.

#### Scenarios Where Replay IS Possible

1. **Ethereum PoW fork** (historical precedent: ETC, ETH PoW fork of 2022): After a hard fork, both chains share the same asset addresses. A signature valid on the original chain is immediately valid on the fork.

2. **New IPOR deployment on a chain with coinciding addresses**: If IPOR deploys on a new chain where an asset is deployed at the same address (e.g., deterministic CREATE2 deployment, or a chain bootstrapped from an Ethereum state snapshot).

3. **USDM token**: If USDM is deployed via CREATE2 at the same address on multiple chains, the attack vector is immediately active.

4. **Testnet/staging environments**: Testnet deployments using the same asset addresses as mainnet (common practice) allow signature reuse from mainnet operations.

### Attack Scenario (in a fork scenario)

```
1. Original chain: messageSigner generates RiskIndicators signature
   - maxCollateralRatio = 0.9e18
   - maxCollateralRatioPerLeg = 0.48e18
   - maxLeveragePerLeg = 1000e18
   - baseSpreadPerLeg = 0
   - fixedRateCapPerLeg = 0.05e18
   - demandSpreadFactor = 1000
   - expiration = block.timestamp + 1 hour
   - asset = 0xA0b86991...  (same address on both chains after fork)
   - Signature: bytes sig = sign(hash)

2. Fork event occurs, creating Fork Chain (same chainId temporarily)

3. Attacker takes SAME signature, sends it on Fork Chain
   - hash.recover(sig) == messageSigner ← VALID (same hash, same key)
   - block.timestamp < expiration ← VALID (within expiry window)
   
4. Attacker opens swaps on Fork Chain using the original chain's signed parameters
   - The RiskIndicators may not reflect current Fork Chain market conditions
   - The signer may have intended to revoke these parameters but cannot because
     there is NO on-chain revocation mechanism
```

### Why This Matters Even Without a Fork

The design flaw is architecturally significant because:

1. **No on-chain revocation**: The only way to invalidate a signature is to wait for it to expire. If a signature is replayed on another chain before expiry, no emergency revocation is possible.

2. **EIP-712 non-compliance**: Best practice is to always include `chainId`. Auditors and users expect EIP-712 compliance.

3. **Future deployments**: As IPOR potentially expands to more chains, the risk of coinciding addresses increases.

---

## Proof of Concept

The following demonstrates that the same hash is produced for two different chains if the asset address is identical:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract ReplayDemo {
    // This would be called on BOTH Ethereum (chainId=1) and another chain
    // If asset = same address on both, hash is identical
    function hashOnChain1(address asset) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            uint256(0.9e18),   // maxCollateralRatio
            uint256(0.48e18),  // maxCollateralRatioPerLeg  
            uint256(1000e18),  // maxLeveragePerLeg
            uint256(0),        // baseSpreadPerLeg
            uint256(0.05e18),  // fixedRateCapPerLeg
            uint256(1000),     // demandSpreadFactor
            uint256(block.timestamp + 3600),  // expiration
            asset,
            uint256(0),        // tenor = 28 days
            uint256(0)         // direction = PAY_FIXED
            // NO chainId!
        ));
    }
    // hashOnChain1(sameAssetAddr) == hashOnChain2(sameAssetAddr) on any chain
}
```

The verify call on any chain:
```solidity
// RiskIndicatorsValidatorLib.verify:
bytes32 hash = hashRiskIndicatorsInputs(inputs, asset, tenor, direction);
require(hash.recover(inputs.signature) == signerAddress, ...);
// → PASSES on both chains if asset address is identical
```

---

## Root Cause

`hashRiskIndicatorsInputs` is a `pure` function that cannot access `block.chainid` directly. The chain ID must be passed as a parameter or captured in a stored domain separator (EIP-712 style).

---

## Recommended Fix

**Option A — Add chainId as parameter (simple fix):**

```solidity
function hashRiskIndicatorsInputs(
    AmmTypes.RiskIndicatorsInputs memory inputs,
    address asset,
    uint256 tenor,
    uint256 direction
) private view returns (bytes32) {  // view to access block.chainid
    return
        keccak256(
            abi.encodePacked(
                inputs.maxCollateralRatio,
                inputs.maxCollateralRatioPerLeg,
                inputs.maxLeveragePerLeg,
                inputs.baseSpreadPerLeg,
                inputs.fixedRateCapPerLeg,
                inputs.demandSpreadFactor,
                inputs.expiration,
                asset,
                tenor,
                direction,
                block.chainid  // ← ADD THIS
            )
        );
}
```

Note: change `private pure` to `private view` to access `block.chainid`.

**Option B — Full EIP-712 compliance (preferred):**

Implement a proper EIP-712 domain separator that includes:
- `name`
- `version`
- `chainId`
- `verifyingContract`

---

## Severity Justification

| Criterion | Assessment |
|-----------|------------|
| Exploitable in current production | Limited (asset addresses differ by chain) |
| Exploitable after fork or new deployment | YES |
| Requires attacker action | Passively replay signed message |
| Funds at risk | Swaps opened at potentially manipulated risk parameters |
| Complexity | Low (just reuse an existing signed message) |
| EIP standards compliance | Violates EIP-712 recommendation |

**Immunefi Severity: Medium** — Design flaw with limited current impact but real risk in fork scenarios or new deployments. The fix is trivial (add one line).

---

## Affected Contracts (Production Mainnet)

| Contract | Address | Role |
|----------|---------|------|
| `IporProtocolRouter` | `0x16d104009964e694761C0bf09d7Be49B7E3C26fd` | Entry point using RiskIndicators |
| `AmmOpenSwapServiceUsdt` | (underlying service) | Validates signatures |
| `AmmCloseSwapServiceUsdt` | (underlying service) | Validates signatures |
| `RiskIndicatorsValidatorLib` | (library, embedded in services) | **Contains the bug** |
