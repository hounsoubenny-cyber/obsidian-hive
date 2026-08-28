"""RaceCondition — TOCTOU sur une opération sensible sans verrou atomique."""
import time
import threading
from .base import Unit, UnitCtx

ACCOUNT_BALANCE = {"default": 100}
_lock_free_by_design = True  # volontairement pas de threading.Lock ici


def make_units(resource):
    balances = ACCOUNT_BALANCE

    def withdraw_no_lock(ctx: UnitCtx):
        body = ctx.raw_json()
        amount = float(body.get("amount", 10))
        account = body.get("account", "default")
        balance = balances.get(account, 100)
        # fenêtre TOCTOU volontaire : lecture, pause, puis écriture (pas atomique)
        if balance >= amount:
            time.sleep(0.01)  # simule un traitement, élargit la fenêtre de course
            balances[account] = balance - amount
            success = True
        else:
            success = False
        return {"account": account, "balance_before": balance, "withdrawn": amount if success else 0,
                "balance_after": balances.get(account, 100), "success": success,
                "note": f"retrait sur {resource} sans verrou atomique : requêtes concurrentes peuvent dépasser le solde"}

    def coupon_redeem_no_lock(ctx: UnitCtx):
        code = ctx.value("PROMO10")
        redeemed_key = f"coupon:{code}"
        already = balances.get(redeemed_key, 0)
        time.sleep(0.01)
        balances[redeemed_key] = already + 1
        return {"coupon_code": code, "times_redeemed_by_this_process": balances[redeemed_key],
                "note": f"redeem de coupon sur {resource} sans verrou : utilisable plusieurs fois en concurrence"}

    return [
        Unit("RaceCondition", "withdraw_toctou_no_lock", "json", "amount",
             f"retrait de fonds sur {resource} avec fenêtre TOCTOU non protégée", withdraw_no_lock, "hard"),
        Unit("RaceCondition", "coupon_redeem_toctou_no_lock", "form", "code",
             "coupon de réduction réutilisable via appels concurrents", coupon_redeem_no_lock, "hard"),
    ]
