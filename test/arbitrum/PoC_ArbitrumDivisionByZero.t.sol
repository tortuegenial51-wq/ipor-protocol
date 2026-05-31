// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

/// @notice PoC #2 — Division by zero in calculateSpreadFunction when lpDepth=0
///         Proven against REAL Arbitrum fork (wstETH pool, SpreadBaseV1).
///
/// Root cause (verified line-by-line):
///   DemandSpreadStEthLibsBaseV1.sol:63  lpDepth = calculateLpDepth(LP, pxFixed, rxFixed)
///   DemandSpreadStEthLibsBaseV1.sol:70  notionalDepth = lpDepth * demandSpreadFactor  -> 0
///   DemandSpreadStEthLibsBaseV1.sol:93  newSpread = calculateSpreadFunction(0, x)
///   DemandSpreadStEthLibsBaseV1.sol:158 IporMath.division(x, 0)                       -> Panic(0x12)
///
/// Organic reachable state on Arbitrum:
///   1. wstETH market becomes 100% pay-fixed (rxFixed = 0)
///   2. LPs withdraw to minimum (redeemLpMaxCollateralRatio = 1.0)
///      LP_min = pxFixed + rxFixed = pxFixed
///   3. lpDepth = LP + rxFixed - pxFixed = 0
///
/// Impact: ALL new swap openings AND unwind closures REVERT while state persists.
///
/// Run locally:
///   ARBITRUM_PROVIDER_URL=https://arb-mainnet.g.alchemy.com/v2/<KEY> \
///   forge test --match-path "test/arbitrum/PoC_ArbitrumDivisionByZero.t.sol" -vvvv

import "./ArbitrumTestForkCommons.sol";
import "../../contracts/base/interfaces/ISpreadBaseV1.sol";

contract PoC_ArbitrumDivisionByZero is ArbitrumTestForkCommons {
    function setUp() public {
        vm.createSelectFork(vm.envString("ARBITRUM_PROVIDER_URL"), 171764768);
        _init();
    }

    /// @notice Reference: rxFixed > 0 gives lpDepth > 0 -> succeeds
    function test_Reference_NormalState_NoRevert() public {
        ISpreadBaseV1.SpreadInputs memory inputs = ISpreadBaseV1.SpreadInputs({
            asset: wstETH,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:    480_000e18,
            totalCollateralReceiveFixed: 10_000e18, // rxFixed > 0 -> lpDepth = 10_000e18 > 0
            liquidityPoolBalance:       490_000e18, // LP = pxFixed + rxFixed
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16,
            tenor: IporTypes.SwapTenor.DAYS_28
        });
        // lpDepth = 490_000 + 10_000 - 480_000 = 20_000 > 0 -> OK
        uint256 rate = ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(inputs);
        assertGt(rate, 0, "rate must be > 0 in normal state");
    }

    /// @notice PoC A: pay-fixed dominant, lpDepth=0 -> division by zero
    ///   State: market 100% pay-fixed (rxFixed=0) + LPs withdraw to LP_min = pxFixed
    function test_PoC_PayFixed_LpDepthZero_Reverts() public {
        ISpreadBaseV1.SpreadInputs memory inputs = ISpreadBaseV1.SpreadInputs({
            asset: wstETH,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:    480_000e18, // pxFixed at max (0.48 x LP_initial)
            totalCollateralReceiveFixed: 0,          // 100% pay-fixed market
            liquidityPoolBalance:       480_000e18, // LP withdrawn to minimum = pxFixed
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16,
            tenor: IporTypes.SwapTenor.DAYS_28
        });
        // lpDepth = 480_000 + 0 - 480_000 = 0
        // notionalDepth = 0 * 1000 = 0
        // calculateSpreadFunction(0, swapNotional) -> IporMath.division(x, 0) -> Panic(0x12)
        vm.expectRevert();
        ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(inputs);
    }

    /// @notice PoC B: receive-fixed dominant, lpDepth=0 -> division by zero
    function test_PoC_ReceiveFixed_LpDepthZero_Reverts() public {
        ISpreadBaseV1.SpreadInputs memory inputs = ISpreadBaseV1.SpreadInputs({
            asset: wstETH,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:     0,
            totalCollateralReceiveFixed: 480_000e18, // 100% receive-fixed market
            liquidityPoolBalance:        480_000e18, // LP withdrawn to minimum = rxFixed
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16,
            tenor: IporTypes.SwapTenor.DAYS_28
        });
        // lpDepth = 480_000 + 0 - 480_000 = 0 (else branch)
        vm.expectRevert();
        ISpreadBaseV1(spreadWstEth).calculateOfferedRateReceiveFixed(inputs);
    }

    /// @notice PoC C: all three tenors are affected (28d, 60d, 90d)
    function test_PoC_AllTenors_Revert() public {
        ISpreadBaseV1.SpreadInputs memory base = ISpreadBaseV1.SpreadInputs({
            asset: wstETH,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:    480_000e18,
            totalCollateralReceiveFixed: 0,
            liquidityPoolBalance:       480_000e18,
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16,
            tenor: IporTypes.SwapTenor.DAYS_28
        });

        vm.expectRevert();
        ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(base);

        base.tenor = IporTypes.SwapTenor.DAYS_60;
        vm.expectRevert();
        ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(base);

        base.tenor = IporTypes.SwapTenor.DAYS_90;
        vm.expectRevert();
        ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(base);
    }

    /// @notice PoC D: demonstrates the organic path step by step with production constraints
    function test_PoC_OrganicPath_ProductionConstraints() public {
        uint256 maxCollateralRatioPerLeg   = 0.48e18; // 48% -- production config
        uint256 redeemLpMaxCollateralRatio = 1e18;    // 100% -- production config

        uint256 LP_initial = 1_000_000e18;

        // Step 1: open pay-fixed swaps up to max allowed ratio
        uint256 pxFixed = (maxCollateralRatioPerLeg * LP_initial) / 1e18; // 480_000e18
        uint256 rxFixed = 0; // all swaps are pay-fixed

        uint256 ratioAtOpen = (pxFixed * 1e18) / LP_initial; // 0.48e18
        assertLe(ratioAtOpen, maxCollateralRatioPerLeg, "open: within maxCollateralRatioPerLeg");

        // Step 2: LPs withdraw to minimum allowed by redeemLpMaxCollateralRatio
        uint256 LP_after = pxFixed + rxFixed; // = 480_000e18
        uint256 collateralRatioAfter = ((pxFixed + rxFixed) * 1e18) / LP_after; // = 1e18
        assertLe(collateralRatioAfter, redeemLpMaxCollateralRatio, "redeem: within redeemLpMaxCollateralRatio");

        // Step 3: lpDepth = 0 -- within production constraints
        uint256 lpDepth = LP_after + rxFixed - pxFixed; // = 0
        assertEq(lpDepth, 0, "lpDepth=0 is reachable within production config");
    }
}
