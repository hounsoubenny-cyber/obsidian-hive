#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul 17 06:59:48 2026

@author: hounsousamuel
"""

"""
human_in_loop.py

Outil générique de confirmation humaine pour agents/tools async.

Principe :
    - `confirm()` est un décorateur qui wrap n'importe quelle méthode async
      pour exiger une confirmation humaine avant exécution.
    - Le décorateur est agnostique du transport : il délègue tout à un objet
      `confirmer` (callable stateful) injecté au moment du wrap.
    - Deux implémentations fournies :
        * InputConfirmer  -> confirmation via input() (tests, CLI, debug)
        * WSConfirmer     -> confirmation via WebSocket (prod)

Usage typique :

    confirmer = WSConfirmer()                 # ws_send attaché plus tard
    confirm_ = partial(confirm, confirmer)

    class CoreTools:
        @confirm_(risk="high", timeout=300)
        async def delete_firewall_rule(self, rule_id: str):
            ...

Dans ta route WS, à la connexion :

    confirmer.attach(lambda data: ws_manager.send_to(username, data))

et à la déconnexion :

    confirmer.detach()

Quand la réponse humaine arrive (message entrant "confirmation_response") :

    confirmer.resolve(req_id, approved=True)
"""

import inspect
import asyncio
from functools import wraps
from typing import Any, Awaitable, Callable, NamedTuple, Optional
from uuid import uuid4
from modules_utils.logger import get_logger
logger = get_logger("human_in_loop")


# --------------------------------------------------------------------------- #
# Types & exceptions
# --------------------------------------------------------------------------- #

class Decision(NamedTuple):
    """Résultat d'une demande de confirmation."""
    approved: bool
    reason: Optional[str] = None


class ConfirmationTimeout(Exception):
    """Levée quand l'humain n'a pas répondu dans le délai imparti."""

    def __init__(self, tool_name: str, req_id: str):
        self.tool_name = tool_name
        self.req_id = req_id
        super().__init__(f"Timeout en attente de confirmation pour '{tool_name}' (req_id={req_id})")


class ConfirmationDenied(Exception):
    """Levée quand l'humain a explicitement refusé l'action."""

    def __init__(self, tool_name: str, reason: Optional[str] = None):
        self.tool_name = tool_name
        self.reason = reason
        msg = f"Confirmation refusée pour '{tool_name}'"
        if reason:
            msg += f" (raison: {reason})"
        super().__init__(msg)


class ConfirmerNotAttachedError(Exception):
    """Levée quand une confirmation est demandée mais aucun canal (WS) n'est
    actuellement attaché — typiquement : l'admin n'est pas connecté."""


# Signature attendue pour tout "confirmer" :
#   async def __call__(self, *, req_id: str, tool_name: str, risk: str, args: dict) -> Decision
Confirmer = Callable[..., Awaitable[Decision]]


# --------------------------------------------------------------------------- #
# Le décorateur
# --------------------------------------------------------------------------- #

def confirm(confirmer: Confirmer, risk: str = "medium", timeout: int = 120):
    """Wrap une méthode async pour exiger une confirmation humaine avant exécution.

    Args:
        confirmer: callable stateful (voir InputConfirmer / WSConfirmer) qui
            porte réellement la logique de notification + attente de réponse.
        risk: niveau de risque de l'action ("low", "medium", "high", "critical").
            Transmis tel quel au confirmer, libre à lui de s'en servir
            (ex: couleur du prompt UI, auto-approve, etc).
        timeout: délai max en secondes avant d'abandonner la demande.

    Raises:
        ConfirmationTimeout: si personne ne répond dans le délai.
        ConfirmationDenied: si la réponse est un refus.

    Note: le confirmer doit être disponible au moment où ce décorateur est
    appliqué (à la définition de la classe/fonction). Pour une classe où le
    confirmer n'est connu qu'à l'instanciation (ex: injecté via __init__),
    voir confirm_self() ci-dessous à la place.
    """
    def decorator(fn):
        sig = inspect.signature(fn)
        fn_is_async = asyncio.iscoroutinefunction(fn)

        @wraps(fn)
        async def wrapper(self, *args, **kwargs):
            req_id = str(uuid4())
            bound = sig.bind_partial(self, *args, **kwargs)
            bound.apply_defaults()
            all_args = dict(bound.arguments)
            all_args.pop("self", None)  # pas utile à montrer à l'humain

            logger.info("Confirmation requise: tool=%s risk=%s req_id=%s", fn.__name__, risk, req_id)

            try:
                decision = await asyncio.wait_for(
                    confirmer(req_id=req_id, tool_name=fn.__name__, risk=risk, args=all_args),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("Confirmation expirée: tool=%s req_id=%s", fn.__name__, req_id)
                raise ConfirmationTimeout(fn.__name__, req_id)

            if not decision.approved:
                logger.info("Confirmation refusée: tool=%s req_id=%s raison=%s",
                            fn.__name__, req_id, decision.reason)
                raise ConfirmationDenied(fn.__name__, decision.reason)

            logger.info("Confirmation accordée: tool=%s req_id=%s", fn.__name__, req_id)
            if fn_is_async:
                return await fn(self, *args, **kwargs)
            return fn(self, *args, **kwargs)

        return wrapper
    return decorator

def confirm_dynamic(confirmer: Confirmer, risk_fn, timeout: int = 120, confirmer_attr: str = "confirmer"):
    """Variante de confirm() où le niveau de risque est CALCULÉ à partir
    des arguments de l'appel plutôt que fixé à la décoration.

    Args:
        risk_fn: callable(**kwargs) -> str, reçoit les mêmes kwargs que la
            méthode décorée (hors self) et retourne le risk level à utiliser
            pour CET appel précis.
        timeout, confirmer_attr: voir confirm_self().

    Exemple : update_asset est "medium" normalement, mais "high" si
    restart_workflow=True (ça interrompt et relance le workflow en direct) :

        def _update_asset_risk(**kwargs):
            return "high" if kwargs.get("restart_workflow") else "medium"

        @confirm_self_dynamic(risk_fn=_update_asset_risk, timeout=120)
        @entry_model(UpdateAssetEntry)
        @timer
        async def update_asset_core_tool(self, asset_id, attrs, restart_workflow=False):
            ...
    """
    def decorator(fn):
        sig = inspect.signature(fn)
        fn_is_async = asyncio.iscoroutinefunction(fn)

        @wraps(fn)
        async def wrapper(self, *args, **kwargs):
            req_id = str(uuid4())
            bound = sig.bind_partial(self, *args, **kwargs)
            bound.apply_defaults()
            all_args = dict(bound.arguments)
            all_args.pop("self", None)
            risk = risk_fn(**all_args)
            logger.info("Confirmation requise: tool=%s risk=%s req_id=%s", fn.__name__, risk, req_id)

            try:
                decision = await asyncio.wait_for(
                    confirmer(req_id=req_id, tool_name=fn.__name__, risk=risk, args=all_args),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("Confirmation expirée: tool=%s req_id=%s", fn.__name__, req_id)
                raise ConfirmationTimeout(fn.__name__, req_id)

            if not decision.approved:
                logger.info("Confirmation refusée: tool=%s req_id=%s raison=%s",
                            fn.__name__, req_id, decision.reason)
                raise ConfirmationDenied(fn.__name__, decision.reason)

            logger.info("Confirmation accordée: tool=%s risk=%s req_id=%s", fn.__name__, risk, req_id)
            if fn_is_async:
                return await fn(self, *args, **kwargs)
            return fn(self, *args, **kwargs)

        return wrapper
    return decorator


def confirm_self(risk: str = "medium", timeout: int = 120, confirmer_attr: str = "confirmer"):
    """Variante de confirm() pour les méthodes d'instance d'une classe où le
    confirmer n'est connu qu'à l'instanciation (injecté via __init__ et
    stocké sur self, ex: self.confirmer), plutôt qu'au moment de la
    décoration (qui a lieu à la définition de la classe, donc trop tôt).

    Args:
        risk, timeout: voir confirm().
        confirmer_attr: nom de l'attribut d'instance portant le confirmer
            (par défaut "confirmer", cf. CoreTools.confirmer).
    """
    def decorator(fn):
        fn_is_async = asyncio.iscoroutinefunction(fn)
        sig = inspect.signature(fn)

        @wraps(fn)
        async def wrapper(self, *args, **kwargs):
            confirmer = getattr(self, confirmer_attr)
            req_id = str(uuid4())
            bound = sig.bind_partial(self, *args, **kwargs)
            bound.apply_defaults()
            all_args = dict(bound.arguments)
            all_args.pop("self", None)

            logger.info("Confirmation requise: tool=%s risk=%s req_id=%s", fn.__name__, risk, req_id)

            try:
                decision = await asyncio.wait_for(
                    confirmer(req_id=req_id, tool_name=fn.__name__, risk=risk, args=all_args),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("Confirmation expirée: tool=%s req_id=%s", fn.__name__, req_id)
                raise ConfirmationTimeout(fn.__name__, req_id)

            if not decision.approved:
                logger.info("Confirmation refusée: tool=%s req_id=%s raison=%s",
                            fn.__name__, req_id, decision.reason)
                raise ConfirmationDenied(fn.__name__, decision.reason)

            logger.info("Confirmation accordée: tool=%s req_id=%s", fn.__name__, req_id)
            if fn_is_async:
                return await fn(self, *args, **kwargs)
            return fn(self, *args, **kwargs)

        return wrapper
    return decorator

def confirm_self_dynamic(risk_fn, timeout: int = 120, confirmer_attr: str = "confirmer"):
    """Variante de confirm_self() où le niveau de risque est CALCULÉ à partir
    des arguments de l'appel plutôt que fixé à la décoration.

    Args:
        risk_fn: callable(**kwargs) -> str, reçoit les mêmes kwargs que la
            méthode décorée (hors self) et retourne le risk level à utiliser
            pour CET appel précis.
        timeout, confirmer_attr: voir confirm_self().

    Exemple : update_asset est "medium" normalement, mais "high" si
    restart_workflow=True (ça interrompt et relance le workflow en direct) :

        def _update_asset_risk(**kwargs):
            return "high" if kwargs.get("restart_workflow") else "medium"

        @confirm_self_dynamic(risk_fn=_update_asset_risk, timeout=120)
        @entry_model(UpdateAssetEntry)
        @timer
        async def update_asset_core_tool(self, asset_id, attrs, restart_workflow=False):
            ...
    """
    def decorator(fn):
        sig = inspect.signature(fn)
        fn_is_async = asyncio.iscoroutinefunction(fn)

        @wraps(fn)
        async def wrapper(self, *args, **kwargs):
            confirmer = getattr(self, confirmer_attr)
            req_id = str(uuid4())
            bound = sig.bind_partial(self, *args, **kwargs)
            bound.apply_defaults()
            all_args = dict(bound.arguments)
            all_args.pop("self", None)
            risk = risk_fn(**all_args)
            logger.info("Confirmation requise: tool=%s risk=%s req_id=%s", fn.__name__, risk, req_id)


            try:
                decision = await asyncio.wait_for(
                    confirmer(req_id=req_id, tool_name=fn.__name__, risk=risk, args=all_args),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("Confirmation expirée: tool=%s req_id=%s", fn.__name__, req_id)
                raise ConfirmationTimeout(fn.__name__, req_id)

            if not decision.approved:
                logger.info("Confirmation refusée: tool=%s req_id=%s raison=%s",
                            fn.__name__, req_id, decision.reason)
                raise ConfirmationDenied(fn.__name__, decision.reason)

            logger.info("Confirmation accordée: tool=%s risk=%s req_id=%s", fn.__name__, risk, req_id)
            if fn_is_async:
                return await fn(self, *args, **kwargs)
            return fn(self, *args, **kwargs)

        return wrapper
    return decorator

# --------------------------------------------------------------------------- #
# Confirmer #1 : mode test / CLI / debug (input() bloquant dans un thread)
# --------------------------------------------------------------------------- #

class InputConfirmer:
    """Confirmer minimal pour les tests et le debug en local.

    Utilise input() dans un thread séparé (asyncio.to_thread) pour ne pas
    bloquer l'event loop pendant que l'utilisateur tape sa réponse.
    """

    async def __call__(self, *, req_id: str, tool_name: str, risk: str, args: dict) -> Decision:
        prompt = f"[{risk.upper()}] Confirmer {tool_name}({args}) ? [y/N] "
        answer = await asyncio.to_thread(input, prompt)
        approved = answer.strip().lower() in ("y", "yes", "o", "oui")
        return Decision(approved=approved)


# --------------------------------------------------------------------------- #
# Confirmer #2 : mode prod, via WebSocket
# --------------------------------------------------------------------------- #

class ChannelAlreadyAttachedError(Exception):
    """Levée par WSConfirmer.attach() si un canal existe déjà pour ce
    username et que force=False — protège contre un double-attach par bug
    (ex: route WS appelée deux fois sans passer par le detach précédent)."""


import contextvars

current_confirm_username: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_confirm_username", default=None
)
"""
A positionner (via .set(username)) au tout début de chaque run agent
(_run_chat/_run_analyze côté core_router.py), le temps de l'exécution du
run. Comme les tools s'exécutent par `await` direct dans la même Task
asyncio (pas de nouvelle Task créée pour chaque tool call), ce contexte
reste visible tout du long de la boucle d'agent — jusque dans
confirm_self() — sans avoir à faire passer `username` explicitement à
travers CoreTools / Coralie / LLMManager.run_agent. Chaque Task a sa
propre copie du contexte, donc deux runs concurrents (2 users, ou plus
tard 2 connexions du même user) ne se marchent pas dessus même s'ils
tournent en même temps.
"""


class WSConfirmer:
    """Confirmer prod : notifie le client via WebSocket et attend sa réponse.

    Multi-canal, indexé par username : chaque connexion admin a son propre
    ws_send. `__call__` route la demande vers le bon canal en lisant
    `current_confirm_username` (voir ce ContextVar ci-dessus) — pas besoin
    que CoreTools/Coralie sachent eux-mêmes "pour qui" ils tournent.
    """

    def __init__(self):
        self._ws_sends: dict[str, Callable[[dict], Any]] = {}
        self._pending: dict[str, asyncio.Future[Decision]] = {}

    def attach(self, username: str, ws_send: Callable[[dict], Any], force: bool = False) -> Callable[[dict], Any]:
        """Branche le canal d'un username. Si un canal existe déjà pour ce
        username, lève ChannelAlreadyAttachedError SAUF si force=True
        (ex: reconnexion volontaire du même admin — cas normal en pratique,
        à passer explicitement pour ne pas masquer un vrai bug ailleurs).

        Retourne `ws_send` tel quel : jeton d'identité à repasser à
        detach(username, ws_send=...) pour éviter qu'une vieille connexion
        n'efface le canal d'une nouvelle (race, voir detach)."""
        if not force and username in self._ws_sends:
            raise ChannelAlreadyAttachedError(
                f"Canal déjà attaché pour {username!r} — passe force=True pour le remplacer"
            )
        self._ws_sends[username] = ws_send
        return ws_send

    def detach(self, username: str, ws_send: Optional[Callable[[dict], Any]] = None) -> None:
        """Débranche le canal d'un username — seulement si `ws_send`
        correspond encore au canal actuellement attaché pour CE username
        (identity check, protège contre le nettoyage tardif d'une
        connexion remplacée entre-temps par une reconnexion)."""
        current = self._ws_sends.get(username)
        if current is None:
            return
        if ws_send is None or current is ws_send:
            self._ws_sends.pop(username, None)

    def is_attached(self, username: str) -> bool:
        return username in self._ws_sends

    async def __call__(self, *, req_id: str, tool_name: str, risk: str, args: dict) -> Decision:
        username = current_confirm_username.get()
        if username is None:
            raise ConfirmerNotAttachedError(
                f"Aucun username dans le contexte pour confirmer '{tool_name}' (req_id={req_id}) "
                "— current_confirm_username.set(...) doit être positionné avant d'exécuter des tools."
            )
        ws_send = self._ws_sends.get(username)
        if ws_send is None:
            raise ConfirmerNotAttachedError(
                f"Aucune connexion active pour {username!r}, impossible de confirmer "
                f"'{tool_name}' (req_id={req_id})"
            )

        fut: asyncio.Future[Decision] = asyncio.get_running_loop().create_future()
        self._pending[req_id] = fut

        try:
            result = ws_send({
                "type": "confirmation_request",
                "req_id": req_id,
                "tool": tool_name,
                "risk": risk,
                "args": args,
            })
            if inspect.isawaitable(result):
                await result
            return await fut
        finally:
            self._pending.pop(req_id, None)

    def resolve(self, req_id: str, approved: bool, reason: Optional[str] = None) -> bool:
        """A appeler depuis ta route WS quand la réponse humaine arrive.

        Retourne False si req_id est inconnu ou déjà résolu (ex: timeout
        déjà déclenché côté serveur) -- utile pour logger un cas tardif
        sans lever d'exception.
        """
        fut = self._pending.get(req_id)
        if fut is None or fut.done():
            logger.warning("resolve() reçu pour req_id inconnu ou déjà résolu: %s", req_id)
            return False
        fut.set_result(Decision(approved=approved, reason=reason))
        return True

    def pending_count(self) -> int:
        """Utile pour du monitoring/debug: nombre de confirmations en attente."""
        return len(self._pending)


if __name__ == "__main__":
    from functools import partial

    # confirmer injecté au niveau module ; en vrai, ça vient de la config
    # (InputConfirmer en test, WSConfirmer en prod).
    _confirmer = InputConfirmer()
    confirm_ = partial(confirm, _confirmer)

    class CoreTools:
        confirmer = _confirmer

        @confirm_(risk="high", timeout=30)
        async def delete_firewall_rule(self, rule_id: str):
            print(f"Règle {rule_id} supprimée.")

        @confirm_self(risk="low", timeout=30)
        async def scan_network(self, subnet: str):
            print(f"Scan de {subnet} lancé.")

    async def main():
        tools = CoreTools()
        try:
            await tools.delete_firewall_rule(rule_id="fw-42")
        except (ConfirmationDenied, ConfirmationTimeout) as e:
            print(f"Action bloquée: {e}")

        try:
            await tools.scan_network("127.0.0.1")
        except (ConfirmationDenied, ConfirmationTimeout) as e:
            print(f"Action bloquée: {e}")

    asyncio.run(main())
