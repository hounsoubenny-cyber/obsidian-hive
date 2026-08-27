#!/usr/bin/env python3
"""
Test end-to-end ObsidianEngine
"""
import asyncio
import tempfile
import os
import sys

from obsidian_hive.core.engine import ObsidianEngine
from obsidian_hive.core.assets.asset_types import WebAsset, Priority

async def test():
    print("=" * 60)
    print("🧪 TEST END-TO-END ObsidianEngine")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        async with ObsidianEngine(
            db_url=f"sqlite+aiosqlite:///{db_path}",
            debug=True,
            do_silence=True,
        ) as engine:

            # 1. Status initial
            print(f"\n✅ Moteur démarré")
            print(f"   {engine.status()}")

            # 2. Ajouter un asset — workflow immédiat
            asset = WebAsset(
                name="DVWA Test",
                url="http://localhost:8080",
                every=9999,  # long pour pas relancer pendant le test
                run_config={
                    "limit_vuln_for_fuzzer": 2,
                    "max_test": 5,
                    "helpers": [{
                        "name": "dvwa_auth",
                        "kwargs": {
                            "base_url": "http://localhost:8080",
                            "username": "admin",
                            "password": "password",
                            "security_level": "low",
                        }
                    }],
                },init_config={},
            )

            result = await engine.add_asset(
                asset, 
                priority=Priority.HIGH,
                manage_immediatly=True
            )
            print(f"\n✅ Asset ajouté: {result}")
            print(f"   Tasks actives: {engine.status()['active_tasks']}")

            # 3. Laisser le scan tourner
            print("\n⏳ Scan en cours, attente 30s...")
            for i in range(30):
                await asyncio.sleep(1)
                status = engine.status()
                print(f"   {i+1}s — tasks actives: {status['active_tasks']}", end="\r")

            print(f"\n\n📊 Status après scan: {engine.status()}")

            # 4. Vérifier que l'asset est en DB
            asset_db = await engine.asset_manager.get_by_item_id(asset.id)
            assert asset_db is not None, "❌ Asset pas trouvé en DB"
            print(f"\n✅ Asset en DB: {asset_db.name} (status: {asset_db.status})")

            # 5. Pause
            await engine.pause_asset(asset.id)
            print(f"\n⏸️  Asset mis en pause")
            print(f"   Tasks actives: {engine.status()['active_tasks']}")

            # 6. Resume
            await engine.resume_asset(asset.id)
            print(f"\n▶️  Asset repris")
            print(f"   Tasks actives: {engine.status()['active_tasks']}")

            # 7. Remove
            await engine.remove_asset(asset.id)
            print(f"\n🗑️  Asset retiré")

            # Vérifier suppression
            asset_db = await engine.asset_manager.get_by_item_id(asset.id)
            assert asset_db is None, "❌ Asset toujours en DB après suppression"
            print(f"✅ Asset bien supprimé de la DB")

        print("\n✅ Moteur arrêté proprement")
        print("\n" + "=" * 60)
        print("✅ TOUS LES TESTS PASSÉS")
        print("=" * 60)

    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)

if __name__ == "__main__":
    asyncio.run(test())