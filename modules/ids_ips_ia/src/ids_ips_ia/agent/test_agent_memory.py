import os
from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools import tool

os.environ["CHROMA_HUGGINGFACE_API_KEY"] = "na"
# os.environ["OPENAI_API_KEY"] = "sk-000000000000000000000000000000000000000000000000"


local_model_path = "/home/hounsousamuel/PROJETS/DEJA_SUR_GIT/Nexus_projet_hackaton/conversation_app/chat_nexus/EMBEDDING"
# Définition du modèle Groq
groq_llm = LLM(
    model="groq/llama-3.3-70b-versatile",
    temperature=0.1, # On reste précis pour la cyber
    api_key="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"
)

# 2. Création d'un outil factice (Tool)
@tool("intel_database")
def threat_intel_search(query: str):
    """Recherche des informations sur des menaces dans une base de données locale."""
    # Simulation d'une base de données
    database = {
        "mirai": "Malware IoT utilisant des identifiants par défaut.",
        "pegasus": "Spyware mobile avancé ciblant iOS et Android.",
        "shield-v1": "Signature détectée dans le projet ShieldAI - Statut: CRITIQUE."
    }
    return database.get(query.lower(), "Menace inconnue dans la base locale.")

# 3. Définition de l'Agent avec Mémoire
cyber_agent = Agent(
    role="Analyste Senior ShieldAI",
    goal="Identifier les menaces et les mémoriser pour les rapports futurs.",
    backstory="Tu es un expert en cyber-intelligence. Tu as une excellente mémoire technique.",
    tools=[threat_intel_search],
    llm=groq_llm,
    memory=True, # On active la mémoire sur l'agent
    verbose=True,
    embedder={
        "provider": "huggingface",
        "config": {
            "model": local_model_path 
        }
    }
)

# 4. Définition des Tâches (Task)
# Tâche 1 : Découvrir une information
task_discovery = Task(
    description="Recherche des infos sur 'shield-v1' dans la base intel et note son statut.",
    expected_output="Le statut de shield-v1.",
    agent=cyber_agent
)

# Tâche 2 : Vérifier la mémoire (on ne lui donne plus l'outil !)
task_recall = Task(
    description="Sans utiliser d'outils, quel était le nom de la menace analysée précédemment et son statut ?",
    expected_output="Rappel précis de la menace et de son statut.",
    agent=cyber_agent
)

# 5. Création du Crew (Le système qui gère la mémoire unifiée)
shield_crew = Crew(
    agents=[cyber_agent],
    tasks=[task_discovery, task_recall],
    process=Process.sequential,
    memory=True, # Active le système de RAG (Short-term/Long-term)
    verbose=True,
    embedder={
        "provider": "huggingface",
        "config": {
            "model": local_model_path 
        }
    },
    manager_llm=groq_llm
)

# Lancement du test
print("🚀 Démarrage du test de mémoire ShieldAI...")
result = shield_crew.kickoff()

print("\n\n" + "="*50)
print("VERDICT FINAL :")
print(result)
print("="*50)