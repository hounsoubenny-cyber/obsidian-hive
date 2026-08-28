"""CredsExpose — fuite d'identifiants/secrets."""
from .base import Unit, UnitCtx, USERS_TABLE

FAKE_CONFIG = {
    "db_password": "P@ssw0rd_DB_TEST",
    "aws_access_key": "AKIAFAKEKEYFORTESTS0001",
    "stripe_secret": "sk_test_FAKESECRETKEY0001",
    "smtp_password": "smtp_test_pwd_2024",
}


def make_units(resource):
    def debug_config_endpoint(ctx: UnitCtx):
        return {"config_leaked": FAKE_CONFIG, "note": f"endpoint de debug {resource} laissé actif en 'prod'"}

    def verbose_error_leak(ctx: UnitCtx):
        val = ctx.value("")
        return {"stack_trace_like": f"Traceback: connecting to db with password={FAKE_CONFIG['db_password']} for {resource} query={val}",
                "note": "message d'erreur qui inclut le mot de passe de connexion DB"}

    def response_header_leak(ctx: UnitCtx):
        return {"headers_would_include": {"X-Api-Key": FAKE_CONFIG["stripe_secret"]},
                "note": "clé API renvoyée dans un header de réponse par erreur"}

    return [
        Unit("CredsExpose", "debug_endpoint_left_on", "path", "resource_name",
             f"endpoint /{resource}/debug/config accessible sans auth", debug_config_endpoint),
        Unit("CredsExpose", "verbose_error_with_secret", "query", "q",
             "message d'erreur détaillé qui expose un secret de config", verbose_error_leak, "medium"),
        Unit("CredsExpose", "secret_in_response_header", "query", "id",
             "secret renvoyé dans un header de réponse HTTP", response_header_leak, "medium"),
    ]
