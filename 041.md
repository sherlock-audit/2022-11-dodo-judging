jayphbee

medium

# `universalApproveMax` will not work for some tokens that don't support approve `type(uint256).max` amount.

## Summary
`universalApproveMax` will not work for some tokens that don't support approve `type(uint256).max` amount.

## Vulnerability Detail
There are tokens that doesn't support approve spender `type(uint256).max` amount. So the `universalApproveMax` will not work for some tokens like `UNI` or `COMP` who will revert when approve `type(uint256).max` amount.

## Impact
Tokens that don't support approve `type(uint256).max` amount could not be swapped by calling `externalSwap` function.

## Code Snippet
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L181-L183
```solidity
            if (approveTarget != address(0)) {
                IERC20(fromToken).universalApproveMax(approveTarget, fromTokenAmount);
            }
```
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/lib/UniversalERC20.sol#L36-L48
```solidity
function universalApproveMax(
        IERC20 token,
        address to,
        uint256 amount
    ) internal {
        uint256 allowance = token.allowance(address(this), to);
        if (allowance < amount) {
            if (allowance > 0) {
                token.safeApprove(to, 0);
            }
            token.safeApprove(to, type(uint256).max);
        }
    }
```

## Tool used

Manual Review

## Recommendation
I would suggest approve only the necessay amount of token to the `approveTarget` instead of the `type(uint256).max` amount.
