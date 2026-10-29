"""Extract WFlib signed-time datasets from verified QUIC session captures."""
import argparse
from collections import defaultdict
from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile

import numpy as np

class CaptureError(ValueError):
    """Capture cannot be represented faithfully in the classifier schema."""


def find_tshark(executable=None):
    found = shutil.which(executable or 'tshark')
    if not found and executable is None:
        candidate = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Wireshark/tshark.exe'
        if candidate.is_file():
            found = str(candidate)
    if not found:
        raise CaptureError('TShark not found. Install Wireshark with TShark, or pass --tshark PATH.')
    return found


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def capture_inputs(paths):
    """Expand verified defense/domain/session folders, excluding diagnostic captures."""
    inputs = []
    for path in paths:
        if not path.is_dir():
            inputs.append((path, {}))
            continue
        sessions = sorted(p for p in (path / 'data' / 'verified').glob('*/*/*') if p.is_dir())
        if not sessions:
            raise CaptureError(f'No verified session folders found in {path}')
        for session in sessions:
            receipt_path = session / 'receipt.json'
            direct = [session / 'pcaps' / name for name in ('traffic.pcap', 'traffic.pcapng')
                      if (session / 'pcaps' / name).is_file()]
            if len(direct) > 1:
                raise CaptureError(f'Ambiguous canonical captures in {session}')
            if not receipt_path.is_file():
                if not direct:
                    raise CaptureError(f'No canonical traffic capture or receipt in {session}')
                domain = session.parent.name
                # Conservatively keep repeated domain/session IDs together across parts/defenses.
                group = 'folder-session:' + hashlib.sha256(
                    json.dumps([domain, session.name]).encode()).hexdigest()
                inputs.append((direct[0], {'domain': domain, 'group_id': group,
                                           'defense': session.parent.parent.name}))
                continue
            try:
                receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
                mode, domain = receipt_path.parts[-4:-2]
                if (receipt['verified'] is not True or receipt['hostname'] != domain or
                        receipt['mode'] != mode):
                    raise ValueError('Receipt verification or folder labels do not match')
                relative = PurePosixPath(receipt['artifact_paths']['pcap'])
                if relative.is_absolute() or '..' in relative.parts or '\\' in str(relative):
                    raise ValueError('Invalid canonical capture path')
                base = (receipt_path.parent / 'pcaps').resolve()
                capture = (direct[0] if direct else base.joinpath(*relative.parts)).resolve()
                if not capture.is_relative_to(base) or not capture.is_file():
                    raise ValueError('Canonical capture is missing or outside the session')
                if capture.name not in ('traffic.pcap', 'traffic.pcapng'):
                    raise ValueError('Expected a canonical traffic capture')
                client, client_port, server, server_port, protocol = receipt['five_tuple']
                if protocol != 17 or any(type(p) is not int or not 1 <= p <= 65535
                                         for p in (client_port, server_port)):
                    raise ValueError('Expected a UDP five-tuple with valid ports')
                client, server = str(ipaddress.ip_address(client)), str(ipaddress.ip_address(server))
                study, slot = receipt['study_sha256'], receipt['slot']
                if not isinstance(study, str) or not study or type(slot) is not int or slot < 0:
                    raise ValueError('Missing study or session slot')
                # Keep matching study/domain slots together across traffic modes.
                group = 'session:' + hashlib.sha256(
                    json.dumps([study, domain, slot]).encode()).hexdigest()
                inputs.append((capture, {'domain': domain, 'group_id': group, 'defense': mode,
                                         'client_addresses': [client],
                                         'expected_flow': ((client, client_port), (server, server_port))}))
            except (KeyError, TypeError, ValueError) as exc:
                raise CaptureError(f'Invalid receipt {receipt_path}: {exc}') from exc
    return inputs


def sequence_from_fields(lines, client_addresses=(), expected_flow=None, seq_len=10000):
    """One observation per UDP datagram, including coalesced QUIC datagrams once."""
    clients = {str(ipaddress.ip_address(a)) for a in client_addresses}
    packets = []
    origin = previous = None
    for line in lines:
        columns = line.rstrip('\r\n').split('\t')
        if len(columns) != 10:
            raise CaptureError('Unexpected TShark fields row')
        timestamp, src4, dst4, src6, dst6, sport, dport, caplen, wirelen, hello = columns
        try:
            src = (str(ipaddress.ip_address(src4 or src6)), int(sport))
            dst = (str(ipaddress.ip_address(dst4 or dst6)), int(dport))
            if expected_flow and (src, dst) not in (expected_flow, expected_flow[::-1]):
                continue
            if int(caplen) < int(wirelen):
                raise CaptureError('Truncated capture frame')
            now = Decimal(timestamp)
            if not now.is_finite():
                raise CaptureError('Nonfinite packet timestamp')
        except (ValueError, InvalidOperation) as exc:
            raise CaptureError(f'Invalid packet fields: {exc}') from exc
        if not clients:
            if '1' not in hello.split(','):
                raise CaptureError('Client role unavailable; supply --client-address or capture the ClientHello')
            clients.add(src[0])
        if (src[0] in clients) == (dst[0] in clients):
            raise CaptureError('Exactly one endpoint must match a client address')
        if previous is not None and now < previous:
            raise CaptureError('Packet timestamps are not ordered')
        previous = now
        if origin is None:
            origin = now
        # Zero is reserved for padding throughout WFlib; retain initial packets.
        elapsed = max(float(now - origin), 1e-9)
        if len(packets) < seq_len:
            packets.append(elapsed if src[0] in clients else -elapsed)
    if not packets:
        raise CaptureError('No matching QUIC datagrams found')
    result = np.zeros(seq_len, dtype=np.float64)
    result[:len(packets)] = packets
    return result


def extract_capture(path, tshark, client_addresses=(), expected_flow=None,
                    seq_len=10000, ports=()):
    if os.name == 'nt' and len(str(Path(path).resolve())) >= 260:
        with tempfile.TemporaryDirectory(prefix='wf-') as directory:
            staged = Path(directory) / 'traffic.pcapng'
            shutil.copyfile(path, staged)
            return extract_capture(staged, tshark, client_addresses, expected_flow, seq_len, ports)
    command = [tshark, '-n', '-2', '-r', str(path), '-Y', 'quic && udp',
               '-T', 'fields', '-E', 'occurrence=a']
    for field in ('frame.time_epoch', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
                  'udp.srcport', 'udp.dstport', 'frame.cap_len', 'frame.len', 'tls.handshake.type'):
        command.extend(['-e', field])
    for port in ports or ([expected_flow[1][1]] if expected_flow else []):
        command.extend(['-d', f'udp.port=={port},quic'])
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors,
                              text=True, encoding='utf-8') as process:
            try:
                result = sequence_from_fields(process.stdout, client_addresses, expected_flow, seq_len)
                code = process.wait()
            except BaseException:
                process.kill()
                process.wait()
                raise
            finally:
                process.stdout.close()
        errors.seek(0)
        if code:
            raise CaptureError(f'TShark exited with {code}: {errors.read().decode(errors="replace")}')
    return result


def save_dataset(path, X, y, groups, captures):
    """Replace each dataset only after its complete archive has been written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix='.npz', delete=False) as output:
            temporary = Path(output.name)
            np.savez_compressed(output, X=X, y=y, groups=np.asarray(groups), captures=np.asarray(captures))
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('captures', nargs='+', type=Path,
                        help='Part directories containing data/verified/defense/domain/session, or PCAP files')
    parser.add_argument('--out-dir', type=Path, default=Path('datasets'))
    parser.add_argument('--domain', help='Required ground-truth label for standalone captures')
    parser.add_argument('--group-id', help='Collection group override')
    parser.add_argument('--client-address', action='append', default=[])
    parser.add_argument('--port', action='append', type=int, default=[])
    parser.add_argument('--tshark')
    parser.add_argument('--seq-len', type=int, default=10000)
    parser.add_argument('--features', nargs='*', choices=['TAM', 'TAF', 'MTAF'], default=[],
                        help='Also write derived features using WFlib extractors')
    parser.add_argument('--skip-invalid', action='store_true', help='Skip invalid sessions and report each error')
    args = parser.parse_args()
    if args.seq_len < 1 or any(not 1 <= p <= 65535 for p in args.port):
        parser.error('seq-len must be positive and ports must be 1..65535')
    if args.domain == '' or args.group_id == '':
        parser.error('domain and group-id must be nonempty')
    try:
        inputs = capture_inputs(args.captures)
        if any(not metadata and not args.domain for _, metadata in inputs):
            raise CaptureError('--domain is required for standalone captures')
        if args.domain and any(meta and meta['domain'] != args.domain for _, meta in inputs):
            raise CaptureError('--domain conflicts with session labels')
        labels = {label: i for i, label in enumerate(sorted({meta.get('domain', args.domain) for _, meta in inputs}))}
        tshark = find_tshark(args.tshark)
        batches = defaultdict(list)
        seen = set()
        for capture, metadata in inputs:
            digest = file_digest(capture)
            if digest in seen:
                raise CaptureError(f'Duplicate capture contents: {capture}')
            seen.add(digest)
            try:
                sequence = extract_capture(capture, tshark,
                    client_addresses=args.client_address or metadata.get('client_addresses', ()),
                    expected_flow=metadata.get('expected_flow'), seq_len=args.seq_len, ports=args.port)
            except (OSError, ValueError) as exc:
                if not args.skip_invalid:
                    raise
                print(json.dumps({'capture': str(capture), 'skipped': str(exc)}))
                continue
            defense = metadata.get('defense', 'captures')
            batches[defense].append((sequence, labels[metadata.get('domain', args.domain)],
                                    args.group_id or metadata.get('group_id', digest), str(capture)))
            print(json.dumps({'capture': str(capture), 'packets_retained': int(np.count_nonzero(sequence))}))
        if not batches:
            raise CaptureError('No usable sessions found')
        for defense, rows in batches.items():
            X = np.stack([row[0] for row in rows])
            present = sorted({row[1] for row in rows})
            remap = {label: i for i, label in enumerate(present)}
            defense_labels = {name: remap[label] for name, label in labels.items() if label in remap}
            y = np.asarray([remap[row[1]] for row in rows], dtype=np.int64)
            groups, captures = [row[2] for row in rows], [row[3] for row in rows]
            target = args.out_dir / f'{defense.capitalize()}.npz'
            save_dataset(target, X, y, groups, captures)
            target.with_suffix('.labels.json').write_text(json.dumps(defense_labels, indent=2), encoding='utf-8')
            for feature in dict.fromkeys(args.features):
                from WFlib.tools import data_processor
                # Reuse the exact model feature definitions without multiprocessing overhead.
                process, params, scale = {
                    'TAM': (data_processor.process_TAM, (80, 1800), 1),
                    'TAF': (data_processor.process_TAF, (40, 2000), 1000),
                    'MTAF': (data_processor.process_MTAF, (20, 8000), 1000),
                }[feature]
                derived = np.stack([process(i, sequence * scale, *params)[1]
                                    for i, sequence in enumerate(X)])
                save_dataset(target.with_name(f'{target.stem}_{feature.lower()}.npz'),
                             derived, y, groups, captures)
            print(json.dumps({'output': str(target), 'shape': list(X.shape)}))
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Extraction failed: {exc}\n')


if __name__ == '__main__':
    main()

