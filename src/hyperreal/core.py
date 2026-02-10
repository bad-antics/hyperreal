"""Hyperreality Engine"""
import json,random

class HyperrealEngine:
    EXAMPLES={
        "disneyland":{"domain":"Theme parks","analysis":"More real than reality — Disneyland exists to conceal that all of America is Disneyland",
                      "order":3,"type":"Masks absence of reality"},
        "reality_tv":{"domain":"Media","analysis":"Contestants perform authenticity — the real becomes a genre",
                      "order":4,"type":"Pure simulation"},
        "social_media":{"domain":"Identity","analysis":"Curated selves more real than lived experience",
                        "order":4,"type":"Pure simulation"},
        "news_24_7":{"domain":"Information","analysis":"News creates events rather than reporting them",
                     "order":3,"type":"Masks absence of reality"},
        "shopping_mall":{"domain":"Consumerism","analysis":"Simulated public space replacing genuine community",
                         "order":3,"type":"Masks absence of reality"},
        "deepfakes":{"domain":"Technology","analysis":"Perfect simulation eliminates the concept of original",
                     "order":4,"type":"Pure simulation"},
    }
    
    def analyze_hyperreal(self,example_key):
        return self.EXAMPLES.get(example_key,{})
    
    def measure_simulation_depth(self,phenomena):
        depth=0
        indicators={"mediated":10,"branded":15,"virtual":20,"ai_generated":25,
                    "no_original":30,"self_referential":20,"commercially_driven":15}
        for ind,weight in indicators.items():
            if phenomena.get(ind): depth+=weight
        level="HYPERREAL" if depth>80 else "SIMULATION" if depth>50 else "REPRESENTATION" if depth>20 else "REAL"
        return {"depth_score":min(depth,100),"level":level}
    
    def precession_of_simulacra(self):
        return [
            {"phase":1,"description":"Image reflects reality","era":"Pre-modern"},
            {"phase":2,"description":"Image masks reality","era":"Modern"},
            {"phase":3,"description":"Image masks absence of reality","era":"Postmodern"},
            {"phase":4,"description":"Image bears no relation to reality","era":"Hypermodern"},
        ]
