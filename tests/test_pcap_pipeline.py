import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pcap_pipeline as pipeline


def row(time, src='192.0.2.1', dst='192.0.2.2', sport=50000, dport=443, hello=''):
    return f'{time}\t{src}\t{dst}\t\t\t{sport}\t{dport}\t100\t100\t{hello}\n'


class PipelineTests(unittest.TestCase):
    def test_direction_padding_and_precise_relative_time(self):
        result = pipeline.sequence_from_fields([
            row('1700000000.000000001', hello='1'),
            row('1700000000.000000101', '192.0.2.2', '192.0.2.1', 443, 50000),
        ], seq_len=4)
        np.testing.assert_allclose(result, [1e-9, -1e-7, 0, 0], atol=1e-15)

    def test_filter_exact_flow(self):
        flow = (('192.0.2.1', 50000), ('192.0.2.2', 443))
        result = pipeline.sequence_from_fields([
            row('1', sport=49999), row('2'),
            row('3', '192.0.2.2', '192.0.2.1', 443, 50000),
        ], ['192.0.2.1'], flow, 2)
        np.testing.assert_array_equal(result, [1e-9, -1])

    def test_reject_unknown_direction_and_disordered_time(self):
        with self.assertRaisesRegex(pipeline.CaptureError, 'Client role'):
            pipeline.sequence_from_fields([row('1')])
        with self.assertRaisesRegex(pipeline.CaptureError, 'not ordered'):
            pipeline.sequence_from_fields([row('2'), row('1')], ['192.0.2.1'])

    def test_validate_beyond_truncation(self):
        with self.assertRaisesRegex(pipeline.CaptureError, 'Truncated'):
            pipeline.sequence_from_fields([row('1'), row('2').replace('\t100\t100\t', '\t50\t100\t')],
                                          ['192.0.2.1'], seq_len=1)

    def test_receipt_discovery_and_group_across_defenses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for defense in ('front', 'undefended'):
                session = root / 'data' / 'verified' / defense / 'example.com' / 'visit1'
                (session / 'pcaps').mkdir(parents=True)
                (session / 'pcaps' / 'traffic.pcap').write_bytes(b'capture')
                (session / 'pcaps' / 'diagnostic.pcap').write_bytes(b'ignore')
                receipt = dict(verified=True, hostname='example.com', mode=defense,
                               artifact_paths={'pcap': 'traffic.pcap'},
                               five_tuple=['192.0.2.1', 50000, '192.0.2.2', 443, 17],
                               study_sha256='study', slot=1)
                (session / 'receipt.json').write_text(json.dumps(receipt))
            inputs = pipeline.capture_inputs([root])
            self.assertEqual(len(inputs), 2)
            self.assertEqual(inputs[0][1]['group_id'], inputs[1][1]['group_id'])
            self.assertEqual(inputs[0][1]['expected_flow'][0], ('192.0.2.1', 50000))
            receipt['artifact_paths']['pcap'] = '../traffic.pcap'
            (session / 'receipt.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(pipeline.CaptureError, 'Invalid canonical'):
                pipeline.capture_inputs([root])

    def test_cli_archive_without_pickle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = root / 'data' / 'verified' / 'front' / 'example.com' / 'visit1'
            (session / 'pcaps').mkdir(parents=True)
            (session / 'pcaps' / 'traffic.pcapng').write_bytes(b'capture')
            output = root / 'output'
            with patch('sys.argv', ['pcap_pipeline.py', str(root), '--out-dir', str(output)]), \
                    patch.object(pipeline, 'find_tshark', return_value='tshark'), \
                    patch.object(pipeline, 'extract_capture', return_value=np.array([1e-9, -1., 0.])), \
                    patch('sys.stdout', new_callable=io.StringIO):
                pipeline.main()
            with np.load(output / 'Front.npz', allow_pickle=False) as data:
                self.assertEqual(data['X'].shape, (1, 3))
                np.testing.assert_array_equal(data['y'], [0])
                self.assertTrue(data['groups'][0].startswith('folder-session:'))
            self.assertEqual(json.loads((output / 'Front.labels.json').read_text()), {'example.com': 0})


if __name__ == '__main__':
    unittest.main()
