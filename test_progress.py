"""Arithmetic/parameter guard controls; process tests live in run_spike.py check."""
import copy
import unittest

from run_spike import validate_progress


def histogram():
    # Two samples of 3 and 5 ticks: bins [2,3] and [4,7].
    bins = [0] * 65
    bins[2] = bins[3] = 1
    return dict(count=2, totalTicks=8, minimumTicks=3, maximumTicks=5, bins=bins)


def fixture():
    h = histogram()
    zero = dict(count=2, totalTicks=0, minimumTicks=0, maximumTicks=0, bins=[2] + [0] * 64)
    return dict(progressDiagnostics=True, progressSampleEvery=64, dataWrites=65, elapsedSeconds=1,
                progress=dict(clockFrequency=1000, creditEpisodes=2, creditChannelReads=3,
                              creditChannelReadsReady=1, creditChannelReadsAwaited=2, dataWritesReady=7,
                              creditWait=copy.deepcopy(h), write=copy.deepcopy(h),
                              invocation=zero, remaining=copy.deepcopy(h)))


class ProgressGuards(unittest.TestCase):
    def test_valid_counts_and_legacy_off(self):
        validate_progress(fixture(), True, 64, True)
        validate_progress({}, False, 64, True, require_schema=False)

    def test_rejects_missing_new_schema_and_enabled_legacy(self):
        for enabled, required in [(False, True), (True, False)]:
            with self.assertRaises(RuntimeError):
                validate_progress({}, enabled, 64, True, required)

    def test_rejects_false_observations(self):
        changes = [lambda p: p.update(progressSampleEvery=8),
                   lambda p: p['progress'].update(creditChannelReadsAwaited=3),
                   lambda p: p['progress'].update(dataWritesReady=66),
                   lambda p: p['progress']['write'].update(count=1),
                   lambda p: p['progress']['remaining'].update(totalTicks=7),
                   lambda p: p['progress']['write']['bins'].__setitem__(2, 0),
                   lambda p: p.update(elapsedSeconds=.001)]
        for change in changes:
            with self.subTest(change=change):
                p = fixture()
                change(p)
                with self.assertRaises(RuntimeError):
                    validate_progress(p, True, 64, True)

    def test_rejects_unexpected_counters(self):
        for enabled, sender in [(False, True), (True, False)]:
            p = fixture()
            p['progressDiagnostics'] = enabled
            with self.assertRaises(RuntimeError):
                validate_progress(p, enabled, 64, sender)


if __name__ == '__main__':
    unittest.main()
