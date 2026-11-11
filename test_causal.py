"""Publication guards: corruption must fail without running benchmark endpoints."""
import copy
import json
from pathlib import Path
import unittest
from analyze_causal import validate, summary

class CausalEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads((Path(__file__).parent/'results/causal-investigation/measurements.json').read_text())

    def reject(self,change):
        data=copy.deepcopy(self.data);change(data)
        with self.assertRaises((ValueError,KeyError,TypeError,RuntimeError)):validate(data,source_check=False)

    def test_complete_export(self):
        validate(self.data)
        expected=json.loads((Path(__file__).parent/'results/causal-investigation/summary.json').read_text())
        self.assertEqual(summary(self.data),expected)

    def test_missing_attempt(self):self.reject(lambda d:d['blocks'][0]['runs'].pop())
    def test_false_measurement_class(self):self.reject(lambda d:d['blocks'][-1].__setitem__('measurementClass','uninstrumented'))
    def test_false_rate(self):self.reject(lambda d:d['blocks'][0]['runs'][0]['metrics'].__setitem__('framesPerSecond',1))
    def test_missing_workload(self):self.reject(lambda d:d['blocks'][0]['build'].__setitem__('workloadSha256',{}))
    def test_duplicate_profile(self):self.reject(lambda d:d['profiles'].__setitem__(0,d['profiles'][1]))
    def test_false_module_group(self):self.reject(lambda d:d['profiles'][0]['functions'][0].__setitem__('module','invented'))
    def test_false_profile_percentage(self):self.reject(lambda d:d['profiles'][0]['functions'][0].__setitem__('percentage',0))
    def test_false_named_samples(self):self.reject(lambda d:d['profiles'][0].__setitem__('unambiguousNamedSamples',-1))
    def test_false_native_loss(self):self.reject(lambda d:d['nativeTrace'].__setitem__('lossDeclarations',0))
    def test_missing_calibration(self):self.reject(lambda d:d['calibration'].pop())
    def test_false_filtered_cpu(self):self.reject(lambda d:d['calibration'][-1]['phases'][-1].__setitem__('selectedThreadCpuMilliseconds',1))
    def test_missing_progress(self):self.reject(lambda d:d['blocks'][5]['runs'][0]['phases']['client'][1].__setitem__('progress',None))
    def test_private_path(self):self.reject(lambda d:d.__setitem__('path','/home/private/result'))

if __name__=='__main__':unittest.main()
