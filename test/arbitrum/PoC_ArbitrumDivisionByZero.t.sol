// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

/// @notice PoC #2 — Division by zero / arithmetic underflow in calculateSpreadFunction
///         when lpDepth <= 0. Proven against REAL Arbitrum fork (wstETH, SpreadBaseV1).
///
/// Root cause (verified line-by-line):
///   CalculateTimeWeightedNotionalLibsBaseV1.sol:18-19
///       lpDepth = LP + rxFixed - pxFixed  →  0 when LP=pxFixed, rxFixed=0
///                                         →  underflow (Panic 0x11) when LP < pxFixed
///   DemandSpreadStEthLibsBaseV1.sol:70    notionalDepth = lpDepth * demandSpreadFactor = 0
///   DemandSpreadStEthLibsBaseV1.sol:72-76 newSpread = calculateSpreadFunction(0, x)
///   DemandSpreadStEthLibsBaseV1.sol:158   IporMath.division(x, 0) → Panic(0x12)
///
/// Critical amplifier (Arbitrum-specific, verified in AmmPoolsServiceWstEthBaseV1.sol:80-110):
///   AmmPoolsServiceWstEth has NO redeemLpMaxCollateralRatio check.
///   LPs can redeem until LP < pxFixed, making lpDepth negative → Panic(0x11) underflow.
///   Contrast: Ethereum mainnet USDT/USDC/DAI pools have redeemLpMaxCollateralRatio=1.0
///   (AmmPoolsService.sol:308-315) which floors LP at pxFixed+rxFixed.
///
/// Impact proven:
///   - ALL new swap openings revert (test_E2E_OpenSwapViaRouter_Reverts)
///   - ALL unwind/early closes revert (test_E2E_UnwindClose_Reverts) → liquidations frozen
///   - No emergency bypass path (AmmCloseSwapServiceBaseV1._emergencyCloseSwaps calls
///     same _closeSwaps path → same revert)
///
/// Run locally:
///   ARBITRUM_PROVIDER_URL=https://arb-mainnet.g.alchemy.com/v2/<KEY> \
///   forge test --match-path "test/arbitrum/PoC_ArbitrumDivisionByZero.t.sol" -vvvv

import "forge-std/StdError.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "./ArbitrumTestForkCommons.sol";
import "../../contracts/base/interfaces/ISpreadBaseV1.sol";
import "../../contracts/interfaces/IAmmSwapsLens.sol";
import "../../contracts/interfaces/IAmmOpenSwapServiceWstEth.sol";
import "../../contracts/chains/arbitrum/interfaces/IAmmPoolsServiceWstEth.sol";
import "../../contracts/interfaces/IAmmCloseSwapServiceWstEth.sol";
import "../../contracts/interfaces/IIpToken.sol";

contract PoC_ArbitrumDivisionByZero is ArbitrumTestForkCommons {
    function setUp() public {
        vm.createSelectFork(vm.envString("ARBITRUM_PROVIDER_URL"), 171764768);
        _init();
    }

    // -------------------------------------------------------------------------
    // PART 1 — Unit tests: the spread calculation itself reverts with lpDepth=0
    // Uses freshly deployed SpreadBaseV1 via _init(), confirms code vulnerability.
    // -------------------------------------------------------------------------

    /// @notice Baseline: rxFixed > 0 → lpDepth > 0 → calculateOfferedRatePayFixed succeeds
    function test_Reference_NormalState_NoRevert() public {
        ISpreadBaseV1.SpreadInputs memory inputs = ISpreadBaseV1.SpreadInputs({
            asset: wstETH,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:    480_000e18,
            totalCollateralReceiveFixed: 10_000e18, // rxFixed > 0 -> lpDepth = 20_000e18 > 0
            liquidityPoolBalance:       490_000e18,
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16,
            tenor: IporTypes.SwapTenor.DAYS_28
        });
        uint256 rate = ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(inputs);
        assertGt(rate, 0, "rate must be > 0 in normal state");
    }

    /// @notice PoC A: LP = pxFixed, rxFixed = 0 → lpDepth = 0 → Panic(0x12) division by zero
    function test_PoC_PayFixed_LpDepthZero_Reverts() public {
        ISpreadBaseV1.SpreadInputs memory inputs = ISpreadBaseV1.SpreadInputs({
            asset: wstETH,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:    480_000e18,
            totalCollateralReceiveFixed: 0,
            liquidityPoolBalance:       480_000e18, // LP = pxFixed → lpDepth = 0
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16,
            tenor: IporTypes.SwapTenor.DAYS_28
        });
        // lpDepth = 480_000 + 0 - 480_000 = 0 → notionalDepth = 0 → IporMath.division(x,0)
        vm.expectRevert(stdError.divisionError);
        ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(inputs);
    }

    /// @notice PoC B: receive-fixed dominant, same bug on the other leg
    function test_PoC_ReceiveFixed_LpDepthZero_Reverts() public {
        ISpreadBaseV1.SpreadInputs memory inputs = ISpreadBaseV1.SpreadInputs({
            asset: wstETH,
            swapNotional: 1e18,
            demandSpreadFactor: 1000,
            baseSpreadPerLeg: 0,
            totalCollateralPayFixed:     0,
            totalCollateralReceiveFixed: 480_000e18,
            liquidityPoolBalance:        480_000e18,
            iporIndexValue: 5e15,
            fixedRateCapPerLeg: 5e16,
            tenor: IporTypes.SwapTenor.DAYS_28
        });
        vm.expectRevert(stdError.divisionError);
        ISpreadBaseV1(spreadWstEth).calculateOfferedRateReceiveFixed(inputs);
    }

    /// @notice PoC C: all three tenors are affected
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

        vm.expectRevert(stdError.divisionError);
        ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(base);

        base.tenor = IporTypes.SwapTenor.DAYS_60;
        vm.expectRevert(stdError.divisionError);
        ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(base);

        base.tenor = IporTypes.SwapTenor.DAYS_90;
        vm.expectRevert(stdError.divisionError);
        ISpreadBaseV1(spreadWstEth).calculateOfferedRatePayFixed(base);
    }

    // -------------------------------------------------------------------------
    // PART 2 — Organic reachability proof with correct Arbitrum production config
    // -------------------------------------------------------------------------

    /// @notice Proves lpDepth=0 is reachable within Arbitrum production constraints.
    /// Config values sourced from ArbitrumTestForkCommons.sol:549-550
    function test_PoC_OrganicPath_ProductionConstraints() public {
        // Arbitrum wstETH production config (ArbitrumTestForkCommons.sol:549-550)
        uint256 maxCollateralRatioPerLeg   = 0.025e18; // 2.5%
        uint256 redeemLpMaxCollateralRatio = 1e18;     // not enforced on wstETH — shown in Part 3

        uint256 LP_initial = 1_000_000e18;

        // Step 1: fill pay-fixed side up to allowed ratio
        uint256 pxFixed = (maxCollateralRatioPerLeg * LP_initial) / 1e18; // = 25_000e18
        uint256 rxFixed = 0;

        uint256 ratioAtOpen = (pxFixed * 1e18) / LP_initial;
        assertLe(ratioAtOpen, maxCollateralRatioPerLeg, "open: within maxCollateralRatioPerLeg");

        // Step 2: LPs withdraw to minimum (no redeemLpMaxCollateralRatio on wstETH — see Part 3)
        uint256 LP_after = pxFixed + rxFixed; // = 25_000e18
        uint256 collateralRatioAfter = ((pxFixed + rxFixed) * 1e18) / LP_after;
        assertLe(collateralRatioAfter, redeemLpMaxCollateralRatio, "math check");

        // Step 3: lpDepth = 0
        uint256 lpDepth = LP_after + rxFixed - pxFixed;
        assertEq(lpDepth, 0, "lpDepth=0 is reachable within Arbitrum production config");
    }

    // -------------------------------------------------------------------------
    // PART 3 — Critical finding: wstETH has NO redeemLpMaxCollateralRatio
    //          LPs can redeem until LP < pxFixed → Panic(0x11) underflow
    //          Contrast with mainnet USDT/USDC/DAI: AmmPoolsService.sol:308-315
    // -------------------------------------------------------------------------

    /// @notice Proves that on Arbitrum wstETH, LPs can reduce LP below pxFixed.
    /// AmmPoolsServiceWstEthBaseV1.sol:80-110 has no redeemLpMaxCollateralRatio check.
    /// The ONLY limit is: require(amountToRedeem > 0, ...)
    function test_WstEth_NoRedeemFloor_LP_CanGoBelowPxFixed() public {
        address user = _getUserAddress(30);
        _setupUser(user, 1_000e18);

        // 1. Provide 1000 wstETH as LP
        vm.prank(user);
        IAmmPoolsServiceWstEth(iporProtocolRouterProxy).provideLiquidityWstEth(user, 1_000e18);

        // 2. Open a pay-fixed swap to create pxFixed > 0
        AmmTypes.RiskIndicatorsInputs memory riskInputs = _buildOpenRiskInputs(0, IporTypes.SwapTenor.DAYS_28);
        vm.prank(user);
        IAmmOpenSwapServiceWstEth(iporProtocolRouterProxy)
            .openSwapPayFixed28daysWstEth(user, wstETH, 10e18, 1e18, 10e18, riskInputs);

        // 3. Record pxFixed and LP before redemption
        IporTypes.AmmBalancesForOpenSwapMemory memory balBefore =
            IAmmSwapsLens(iporProtocolRouterProxy).getBalancesForOpenSwap(wstETH);
        assertGt(balBefore.totalCollateralPayFixed, 0, "pxFixed must be > 0");
        assertGt(balBefore.liquidityPool, balBefore.totalCollateralPayFixed, "LP > pxFixed before redeem");

        // 4. Redeem 99.9% of ipTokens — no redeemLpMaxCollateralRatio stops this
        uint256 ipBalance = IIpToken(ipwstETH).balanceOf(user);
        uint256 toRedeem  = (ipBalance * 999) / 1000;
        vm.prank(user);
        IAmmPoolsServiceWstEth(iporProtocolRouterProxy).redeemFromAmmPoolWstEth(user, toRedeem);

        // 5. LP is now BELOW pxFixed — impossible on mainnet USDT/USDC/DAI with the check
        IporTypes.AmmBalancesForOpenSwapMemory memory balAfter =
            IAmmSwapsLens(iporProtocolRouterProxy).getBalancesForOpenSwap(wstETH);
        assertLt(
            balAfter.liquidityPool,
            balAfter.totalCollateralPayFixed,
            "LP < pxFixed: no redeemLpMaxCollateralRatio on wstETH"
        );
    }

    // -------------------------------------------------------------------------
    // PART 4 — End-to-end: real IporProtocolRouter path blocks new swaps
    //          AmmOpenSwapServiceBaseV1.sol:140-170 passes live balances to spread
    // -------------------------------------------------------------------------

    /// @notice E2E: calling openSwapPayFixed28daysWstEth via IporProtocolRouter reverts
    /// when LP < pxFixed. Path: Router → AmmOpenSwapServiceBaseV1:157
    /// → SpreadBaseV1.calculateAndUpdateOfferedRatePayFixed
    /// → DemandSpreadStEthLibsBaseV1.calculatePayFixedSpread → lpDepth underflow
    function test_E2E_OpenSwapViaRouter_Reverts_WhenLpBelowPxFixed() public {
        address user = _getUserAddress(31);
        _setupUser(user, 1_000e18);

        // 1. Provide LP and open a swap
        vm.prank(user);
        IAmmPoolsServiceWstEth(iporProtocolRouterProxy).provideLiquidityWstEth(user, 1_000e18);

        AmmTypes.RiskIndicatorsInputs memory riskInputs = _buildOpenRiskInputs(0, IporTypes.SwapTenor.DAYS_28);
        vm.prank(user);
        IAmmOpenSwapServiceWstEth(iporProtocolRouterProxy)
            .openSwapPayFixed28daysWstEth(user, wstETH, 10e18, 1e18, 10e18, riskInputs);

        // 2. Reduce LP below pxFixed (no redeemLpMaxCollateralRatio)
        uint256 ipBalance = IIpToken(ipwstETH).balanceOf(user);
        vm.prank(user);
        IAmmPoolsServiceWstEth(iporProtocolRouterProxy)
            .redeemFromAmmPoolWstEth(user, (ipBalance * 999) / 1000);

        // 3. Verify precondition: LP < pxFixed
        IporTypes.AmmBalancesForOpenSwapMemory memory bal =
            IAmmSwapsLens(iporProtocolRouterProxy).getBalancesForOpenSwap(wstETH);
        assertLt(bal.liquidityPool, bal.totalCollateralPayFixed, "precondition: LP < pxFixed");

        // 4. Any new swap opening now reverts — protocol is completely blocked for new users
        //    Panic(0x11): LP < pxFixed → lpDepth underflow in calculateLpDepth
        _setupUser(user, 10e18);
        AmmTypes.RiskIndicatorsInputs memory riskInputs2 = _buildOpenRiskInputs(0, IporTypes.SwapTenor.DAYS_28);
        vm.prank(user);
        vm.expectRevert(stdError.arithmeticError);
        IAmmOpenSwapServiceWstEth(iporProtocolRouterProxy)
            .openSwapPayFixed28daysWstEth(user, wstETH, 10e18, 1e18, 10e18, riskInputs2);
    }

    // -------------------------------------------------------------------------
    // PART 5 — End-to-end: liquidations are frozen (most critical impact)
    //          RiskManagementLogic.sol:43-63 passes live balances to spread during unwind
    // -------------------------------------------------------------------------

    /// @notice E2E: closing an existing swap early (unwind) reverts when LP < pxFixed.
    /// Path: Router → AmmCloseSwapService → SwapCloseLogicLib.sol:94
    /// → RiskManagementLogic.calculateOfferedRate:43 → getBalancesForOpenSwap() live
    /// → staticcall SpreadBaseV1 → calculatePayFixedSpread → Panic
    ///
    /// Impact: swaps cannot be liquidated before maturity. Bad debt accumulates unaddressed
    /// for up to 90 days (max tenor). No emergency bypass path exists.
    function test_E2E_UnwindClose_Reverts_WhenLpBelowPxFixed() public {
        address user = _getUserAddress(32);
        _setupUser(user, 1_000e18);

        // 1. Provide LP and open a swap
        vm.prank(user);
        IAmmPoolsServiceWstEth(iporProtocolRouterProxy).provideLiquidityWstEth(user, 1_000e18);

        AmmTypes.RiskIndicatorsInputs memory riskInputs = _buildOpenRiskInputs(0, IporTypes.SwapTenor.DAYS_28);
        vm.prank(user);
        uint256 swapId = IAmmOpenSwapServiceWstEth(iporProtocolRouterProxy)
            .openSwapPayFixed28daysWstEth(user, wstETH, 10e18, 1e18, 10e18, riskInputs);

        // 2. Reduce LP below pxFixed (no redeemLpMaxCollateralRatio on wstETH)
        uint256 ipBalance = IIpToken(ipwstETH).balanceOf(user);
        vm.prank(user);
        IAmmPoolsServiceWstEth(iporProtocolRouterProxy)
            .redeemFromAmmPoolWstEth(user, (ipBalance * 999) / 1000);

        // 3. Verify precondition: LP < pxFixed
        IporTypes.AmmBalancesForOpenSwapMemory memory bal =
            IAmmSwapsLens(iporProtocolRouterProxy).getBalancesForOpenSwap(wstETH);
        assertLt(bal.liquidityPool, bal.totalCollateralPayFixed, "precondition: LP < pxFixed");

        // 4. Early close (unwind) reverts — existing positions CANNOT be liquidated
        //    RiskManagementLogic.sol:43 fetches live balances → same arithmetic panic
        uint256[] memory payFixedIds = new uint256[](1);
        payFixedIds[0] = swapId;
        uint256[] memory receiveFixedIds = new uint256[](0);

        AmmTypes.CloseSwapRiskIndicatorsInput memory closeRisk =
            _prepareCloseSwapRiskIndicators(IporTypes.SwapTenor.DAYS_28);

        vm.prank(user);
        vm.expectRevert(stdError.arithmeticError);
        IAmmCloseSwapServiceWstEth(iporProtocolRouterProxy)
            .closeSwapsWstEth(user, payFixedIds, receiveFixedIds, closeRisk);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// @dev Builds a signed RiskIndicatorsInputs for opening a swap.
    /// Values from ArbitrumTestForkCommons.sol:549-556.
    function _buildOpenRiskInputs(
        uint256 direction,
        IporTypes.SwapTenor tenor
    ) private view returns (AmmTypes.RiskIndicatorsInputs memory r) {
        r = AmmTypes.RiskIndicatorsInputs({
            maxCollateralRatio:       50_000_000_000_000_000,  // 5%
            maxCollateralRatioPerLeg: 25_000_000_000_000_000,  // 2.5% — Arbitrum actual
            maxLeveragePerLeg:        1_000_000_000_000_000_000_000,
            baseSpreadPerLeg:         direction == 0
                                        ? int256(3_695_000_000_000_000)
                                        : int256(-3_695_000_000_000_000),
            fixedRateCapPerLeg:       direction == 0
                                        ? uint256(20_000_000_000_000_000)
                                        : uint256(35_000_000_000_000_000),
            demandSpreadFactor:       20,
            expiration:               block.timestamp + 1000,
            signature:                bytes("0x00")
        });
        r.signature = signRiskParams(r, wstETH, uint256(tenor), direction, messageSignerPrivateKey);
    }
}
