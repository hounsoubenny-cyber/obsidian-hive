from apscheduler.schedulers.background import BackgroundScheduler
import time

def ma_tache(nom):
    print(f"✅ {nom} exécutée à {time.strftime('%H:%M:%S')}")

scheduler = BackgroundScheduler()

# Job avec args initial
job_id = scheduler.add_job(
    ma_tache, 
    'interval', 
    seconds=3, 
    id='test',
    args=("Version 1",)
).id

scheduler.start()

# ➜ Le job tourne avec "Version 1" toutes les 3 secondes
time.sleep(5)

# ✅ Modification des arguments
scheduler.modify_job(job_id, args=("Version 2",), s=2)

# ➜ Le job tourne maintenant avec "Version 2" (prochaine exécution)
time.sleep(5)

# ✅ Modification du trigger (intervalle)
scheduler.reschedule_job(job_id, trigger='interval', seconds=5)

# ➜ Le job tourne maintenant toutes les 5 secondes
time.sleep(10)

scheduler.shutdown()