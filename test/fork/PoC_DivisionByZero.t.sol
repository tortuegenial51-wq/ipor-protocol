// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../contracts/libraries/math/IporMath.sol";

/// @notice PoC #2 -- Division by zero in calculateSpreadFunction when lpDepth = 0
///
/// Root cause: calculateLpDepth returns 0 when LP = pxFixed and rxFixed = 0.
/// Then notionalDepth = 0 * demandSpreadFactor = 0 is passed as maxNotional
/// to calculateSpreadFunction, causing IporMath.division(x, 0) -> Panic(0x12).
///
/// Reachable state (no governance change needed):
///   1. Market becomes 100% pay-fixed (rxFixed = 0)
///   2. LPs withdraw to minimum (redeemLpMaxCollateralRatio = 1.0)
///      -> LP_min = pxFixed + rxFixed = pxFixed
///   3. lpDepth = LP + rxFixed - pxFixed = pxFixed + 0 - pxFixed = 0
///
/// Impact: ALL new swap openings AND unwind closures REVERT.
///
/// Verified code sources (all in this repo, line numbers confirmed):
///   - calculateLpDepth:       contracts/amm/spread/CalculateTimeWeightedNotionalLibs.sol:18-19
///   - notionalDepth = 0:      contracts/base/spread/DemandSpreadStableLibsBaseV1.sol:49
///   - IporMath.division(x,0): contracts/libraries/math/IporMath.sol:8-10
///   - No access control:      contracts/amm/spread/SpreadRouter.sol:97-113
///   - Open swap uses live:    contracts/base/amm/services/AmmOpenSwapServiceBaseV1.sol:140-165
///   - Unwind uses live:       contracts/libraries/RiskManagementLogic.sol:43-44
///   - LP withdrawal allowed:  contracts/amm/AmmPoolsService.sol:308-315

contract DivisionHelper {
    /// @dev Exposes IporMath.division so vm.expectRevert() can catch external call revert
    function divide(uint256 x, uint256 y) external pure returns (uint256) {
        return IporMath.division(x, y);
    }
}

contract LpDepthHelper {
    /// @dev Replicates CalculateTimeWeightedNotionalLibs.calculateLpDepth (lines 13-23)
    function calculateLpDepth(
        uint256 liquidityPoolBalance,
        uint256 totalCollateralPayFixed,
        uint256 totalCollateralReceiveFixed
    ) external pure returns (uint256 lpDepth) {
        if (totalCollateralPayFixed >= totalCollateralReceiveFixed) {
            lpDepth = liquidityPoolBalance + totalCollateralReceiveFixed - totalCollateralPayFixed;
        } else {
            lpDepth = liquidityPoolBalance + totalCollateralPayFixed - totalCollateralReceiveFixed;
        }
    }
}

contract PoC_DivisionByZero is Test {
    DivisionHelper divHelper;
    LpDepthHelper lpHelper;

    function setUp() public {
        divHelper = new DivisionHelper();
        lpHelper = new LpDepthHelper();
    }

    /// @notice Step 1: lpDepth = 0 when LP = pxFixed, rxFixed = 0
    function test_Step1_LpDepth_IsZero_WhenLP_EqualsPxFixed() public {
        uint256 LP      = 480_000e18;
        uint256 pxFixed = 480_000e18;
        uint256 rxFixed = 0;

        uint256 lpDepth = lpHelper.calculateLpDepth(LP, pxFixed, rxFixed);

        assertEq(lpDepth, 0, "lpDepth must be 0 when LP = pxFixed and rxFixed = 0");
    }

    /// @notice Step 2: notionalDepth = 0 when lpDepth = 0
    function test_Step2_NotionalDepth_IsZero() public {
        uint256 lpDepth = 0;
        uint256 demandSpreadFactor = 1000;

        // DemandSpreadStableLibsBaseV1.sol:49
        uint256 notionalDepth = lpDepth * demandSpreadFactor;

        assertEq(notionalDepth, 0, "notionalDepth must be 0 when lpDepth = 0");
    }

    /// @notice Step 3: IporMath.division(x, 0) reverts with Panic(0x12)
    function test_Step3_IporMath_Division_ByZero_Reverts() public {
        uint256 weightedNotional = 1e18;

        // IporMath.sol:8-10: z = (x + (y/2)) / y -> Panic(0x12) when y = 0
        vm.expectRevert();
        divHelper.divide(weightedNotional * 1e18, 0);
    }

    /// @notice Step 3b: even division(0, 0) reverts
    function test_Step3b_IporMath_Division_ZeroByZero_Reverts() public {
        vm.expectRevert();
        divHelper.divide(0, 0);
    }

    /// @notice Reference: division works when maxNotional > 0
    function test_Reference_Division_NormalCase_Succeeds() public {
        uint256 lpDepth = 20_000e18;
        uint256 demandSpreadFactor = 1000;
        uint256 notionalDepth = lpDepth * demandSpreadFactor;

        uint256 weightedNotional = 1e18;
        uint256 ratio = divHelper.divide(weightedNotional * 1e18, notionalDepth);

        assertGt(notionalDepth, 0, "notionalDepth must be > 0 for normal operation");
        assertGe(ratio, 0, "ratio computation should succeed");
    }

    /// @notice End-to-end: organic state (LP=pxFixed, rxFixed=0) leads to division by zero
    function test_CompletePath_OrganicState_CausesRevert() public {
        uint256 LP      = 480_000e18;
        uint256 pxFixed = 480_000e18;
        uint256 rxFixed = 0;

        // Step 1: calculateLpDepth returns 0
        uint256 lpDepth = lpHelper.calculateLpDepth(LP, pxFixed, rxFixed);
        assertEq(lpDepth, 0);

        // Step 2: notionalDepth = 0
        uint256 notionalDepth = lpDepth * 1000;
        assertEq(notionalDepth, 0);

        // Step 3: calculateSpreadFunction(0, weightedNotional) -> REVERT
        // Any swapNotional > 0 makes newWeightedNotionalPayFixed > 0 = timeWeightedNotionalReceiveFixed
        // -> calculateSpreadFunction called with maxNotional=0 -> Panic(0x12)
        vm.expectRevert();
        divHelper.divide(1e18 * 1e18, notionalDepth); // simulates line 137
    }

    /// @notice Proves the organic state is reachable within production constraints
    function test_OrganicState_IsWithinProductionConstraints() public {
        // Production config (verified in test/fork/TestForkCommons.sol)
        uint256 maxCollateralRatioPerLeg    = 0.48e18; // 48%
        uint256 redeemLpMaxCollateralRatio  = 1e18;    // 100%

        uint256 LP_initial = 1_000_000e18;

        // Step 1: open pay-fixed swaps to max allowed ratio
        uint256 pxFixed = (maxCollateralRatioPerLeg * LP_initial) / 1e18; // = 480_000e18
        uint256 rxFixed = 0;

        // Verify ratio at open time is within limit
        uint256 ratioAtOpen = (pxFixed * 1e18) / LP_initial;
        assertLe(ratioAtOpen, maxCollateralRatioPerLeg, "open constraint satisfied");

        // Step 2: LPs withdraw -- minimum LP = pxFixed + rxFixed = 480_000
        uint256 LP_after = pxFixed + rxFixed; // minimum allowed

        // Verify withdrawal is within redeemLpMaxCollateralRatio
        uint256 collateralRatioAfter = ((pxFixed + rxFixed) * 1e18) / LP_after;
        assertLe(collateralRatioAfter, redeemLpMaxCollateralRatio, "redeem constraint satisfied");

        // Step 3: lpDepth = 0 -- within production constraints
        uint256 lpDepth = LP_after + rxFixed - pxFixed;
        assertEq(lpDepth, 0, "lpDepth = 0 is reachable within production constraints");
    }
}
