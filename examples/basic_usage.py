from hyperreal.core import HyperrealEngine
h=HyperrealEngine()
for ex in ["disneyland","reality_tv","social_media","deepfakes"]:
    info=h.analyze_hyperreal(ex)
    print(f"{ex}: {info['analysis']}")
print(f"\nSimulation depth: {h.measure_simulation_depth({'virtual':True,'ai_generated':True,'no_original':True})}")
for phase in h.precession_of_simulacra(): print(f"Phase {phase['phase']}: {phase['description']}")
