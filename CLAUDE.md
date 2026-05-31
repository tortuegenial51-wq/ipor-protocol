# CLAUDE.md — Bug Bounty IPOR Protocol

## Règles absolues de méthodologie

```
⚠️  NE PAS HALLUCINER
    Chaque finding doit être vérifié ligne par ligne dans le code source.
    Aucune spéculation. Aucune inférence non vérifiée.
    Si ce n'est pas lu dans le fichier → ce n'est pas dans le rapport.

⚠️  ÊTRE PRÉCIS ET MÉTHODIQUE
    Format obligatoire pour chaque finding :
    - Fichier exact + numéro(s) de ligne
    - Snippet du code vulnérable (copié, pas paraphrasé)
    - Condition exacte qui déclenche la faille
    - Scénario d'exploitation réaliste
    - Statut : CONFIRMÉ / SUSPECT / INFORMATIF
```

---

## Contexte de la mission

**Protocole** : IPOR Protocol — swaps de taux d'intérêt (IRS) décentralisés  
**Réseaux** : Ethereum mainnet, Arbitrum, Base  
**Scope** : Contrats Solidity dans `contracts/`  
**Branche de travail** : `claude/bug-bounty-analysis-8F5m6`  
**Rapport complet** : `SECURITY_ANALYSIS.md`

---

## Architecture rapide

```
IporProtocolRouter (UUPS, point d'entrée)
  ├─ fallback → delegatecall vers service contracts
  ├─ AmmOpenSwapService     — ouverture de swaps
  ├─ AmmCloseSwapService*   — fermeture/liquidation
  ├─ AmmPoolsService        — LP deposit/withdraw
  └─ AmmTreasury (UUPS)     — gestion des fonds (ERC4626)

SpreadRouter (UUPS)
  └─ DemandSpreadStableLibsBaseV1  — calcul du spread ← VULNÉRABLE

IporOracle (UUPS)
  └─ IporLogic  — accrétion quasi-IBT price ← VULNÉRABLE

Libraries critiques :
  - IporMath.sol        — arithmétique en virgule fixe
  - InterestRates.sol   — composé continu (ABDK quad math)
  - RiskIndicatorsValidatorLib.sol  — vérification signatures ECDSA ← VULNÉRABLE
  - SwapLogicBaseV1.sol — calcul PnL
```

---

## Résumé des findings (rapport complet dans SECURITY_ANALYSIS.md)

| # | Sévérité | Titre | Fichier | Ligne | Statut |
|---|----------|-------|---------|-------|--------|
| 1 | 🔴 CRITIQUE | Underflow dans `calculateLpDepth` → DoS spread | `base/spread/CalculateTimeWeightedNotionalLibsBaseV1.sol` | 18-22 | CONFIRMÉ |
| 2 | 🔴 CRITIQUE | Division par zéro `calculateSpreadFunction` si lpDepth=0 | `base/spread/DemandSpreadStableLibsBaseV1.sol` | 137 | CONFIRMÉ |
| 3 | 🟠 HIGH | Signature RiskIndicators sans `block.chainid` | `libraries/RiskIndicatorsValidatorLib.sol` | 36-51 | CONFIRMÉ |
| 4 | 🟠 HIGH | Oracle DoS — overflow `uint64` sur indexValue | `oracles/IporOracle.sol` | 284 | CONFIRMÉ |
| 5 | 🟠 HIGH | Oracle DoS — overflow `uint32` timestamp (2106) | `oracles/IporOracle.sol` | 207, 284 | CONFIRMÉ |
| 6 | 🟡 MEDIUM | ETH bloqué dans le router (appels admin sans reentrancy guard) | `router/IporProtocolRouterEthereum.sol` | 291-398 | CONFIRMÉ |
| 7 | 🟡 MEDIUM | Overflow `uint96` notional storage → DoS à $79B | `amm/spread/SpreadStorageLibs.sol` | 64 | CONFIRMÉ |
| 8 | 🟡 MEDIUM | Accumulation unbounded `quasiIbtPrice` | `oracles/libraries/IporLogic.sol` | 21 | CONFIRMÉ |

---

## Comment vérifier un finding

```bash
# 1. Lire le fichier exact
Read /home/user/ipor-protocol/contracts/<path>

# 2. Chercher les tests existants
grep -r "calculateLpDepth\|calculateSpreadFunction" test/

# 3. Vérifier la version Solidity (0.8.26 = arithmétique vérifiée par défaut)
grep -r "pragma solidity" contracts/ | head -3
```

---

## Ne pas analyser (hors scope ou non-vulnérables confirmés)

- Gouvernance/admin (owner trusted by design)
- Précision WAD standard (rounding intentionnel)
- `block.timestamp` dans swaps (variance ±15s acceptable)
- Reentrancy — protégée correctement (vérifiée dans AccessControl.sol)
