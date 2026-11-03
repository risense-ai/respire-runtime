import copy,importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('feedback_bench',pathlib.Path(__file__).with_name('compare-feedback-bench.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class PairedBench(unittest.TestCase):
 def fixture(self):
  return {'topk':20,'n_entries':25,'params':{'sdk_lock_sha256':'frozen-sdk','embedding_model':'m3'},'results':[{'query':'first','expect':['id'],'ids':['id'],'rank':0},{'query':'second','expect':['id'],'ids':['other','id'],'rank':1}]}
 def test_identical_and_paired_regression_are_not_called_gain(self):
  base=self.fixture();self.assertEqual(module.paired(base,base,iterations=100)['mrr_delta']['interval95'],[0,0])
  changed=copy.deepcopy(base);changed['results'][0].update(ids=['other'],rank=None)
  result=module.paired(base,changed,iterations=100);self.assertEqual(result['hit20_delta']['mean'],-.5);self.assertEqual(result['mrr_delta']['mean'],-.5);self.assertEqual(result['degraded_case_indices'],[0]);self.assertIn('not established',result['holdout_status'])
 def test_changed_inputs_and_duplicate_cases_are_rejected(self):
  base=self.fixture()
  for change in [lambda item:item.update(topk=5),lambda item:item.update(n_entries=26),lambda item:item['params'].update(sdk_lock_sha256='different'),lambda item:item['results'][0].update(query='different'),lambda item:item['results'][0].update(rank=100)]:
   changed=copy.deepcopy(base);change(changed)
   with self.assertRaises(ValueError):module.paired(base,changed,iterations=10)
  base['results']=[base['results'][0]]*2
  with self.assertRaises(ValueError):module.paired(base,base,iterations=10)
if __name__=='__main__':unittest.main()
