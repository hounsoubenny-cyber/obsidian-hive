"""RaceCondition (safe) — opérations sensibles protégées par un verrou atomique."""
import threading
from .base import Unit, UnitCtx

ACCOUNT_BALANCE = {"default": 100}
_LOCK = threading.Lock()
_COUPONS_REDEEMED = set()
_COUPON_LOCK = threading.Lock()


def make_units(resource):
    balances = ACCOUNT_BALANCE

    def withdraw_no_lock(ctx: UnitCtx):
        body = ctx.raw_json()
        amount = float(body.get("amount", 10))
        account = body.get("account", "default")
        with _LOCK:  # section critique atomique : lecture+écriture protégées
            balance = balances.get(account, 100)
            if balance >= amount:
                balances[account] = balance - amount
                success = True
            else:
                success = False
        return {"account": account, "balance_after": balances.get(account, 100), "success": success,
                "note": f"retrait sur {resource} protégé par un verrou atomique"}

    def coupon_redeem_no_lock(ctx: UnitCtx):
        code = ctx.value("PROMO10")
        with _COUPON_LOCK:  # empêche toute double-utilisation concurrente
            already_used = code in _COUPONS_REDEEMED
            if not already_used:
                _COUPONS_REDEEMED.add(code)
        return {"coupon_code": code, "already_used": already_used, "redeemed_now": not already_used,
                "note": f"redeem de coupon sur {resource} protégé par verrou, usage unique garanti"}

    return [
        Unit("RaceCondition", "withdraw_toctou_no_lock", "json", "amount", "verrou atomique sur le retrait", withdraw_no_lock, "hard"),
        Unit("RaceCondition", "coupon_redeem_toctou_no_lock", "form", "code", "verrou atomique, usage unique garanti", coupon_redeem_no_lock, "hard"),
    ]
