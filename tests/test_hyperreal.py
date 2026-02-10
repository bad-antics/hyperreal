import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from hyperreal.core import HyperrealEngine

class TestHyperreal(unittest.TestCase):
    def test_example(self):
        h=HyperrealEngine()
        r=h.analyze_hyperreal("disneyland")
        self.assertEqual(r["order"],3)
    def test_depth(self):
        h=HyperrealEngine()
        r=h.measure_simulation_depth({"mediated":True,"virtual":True,"ai_generated":True,"no_original":True})
        self.assertEqual(r["level"],"HYPERREAL")
    def test_precession(self):
        h=HyperrealEngine()
        r=h.precession_of_simulacra()
        self.assertEqual(len(r),4)

if __name__=="__main__": unittest.main()
