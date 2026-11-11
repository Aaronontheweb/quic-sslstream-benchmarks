"""Read documented gperftools x64 profiles; resolve sampled leaf PCs without nearest-export guesses."""
import bisect
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).parent
ELF_CACHE = {}

def read_profile(path):
    data = path.read_bytes()
    if len(data) < 64:
        raise ValueError('Truncated profile')
    count, words, version, period, padding = struct.unpack_from('<5Q', data)
    if count != 0 or words < 3 or version != 0 or period == 0 or padding != 0:
        raise ValueError('Unsupported x64 profile header')
    offset = (words + 2) * 8
    leaves = Counter()
    depths = Counter()
    records = []
    while True:
        if offset + 16 > len(data):
            raise ValueError('Missing profile trailer')
        count, depth = struct.unpack_from('<2Q', data, offset)
        offset += 16
        if depth < 1 or depth > 1024 or offset + 8 * depth > len(data):
            raise ValueError('Invalid profile stack record')
        stack = struct.unpack_from('<' + 'Q' * depth, data, offset)
        offset += 8 * depth
        if count == 0:
            if depth != 1 or stack[0] != 0:
                raise ValueError('Invalid profile trailer')
            break
        leaves[stack[0]] += count
        depths[depth] += count
        records.append((count, stack))
    mappings = []
    for line in data[offset:].decode('utf-8').splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 5 or not re.fullmatch(r'[0-9a-fA-F]+-[0-9a-fA-F]+', fields[0]):
            continue
        start, end = (int(value, 16) for value in fields[0].split('-'))
        mappings.append(dict(start=start, end=end, permissions=fields[1], offset=int(fields[2], 16),
                             path=fields[5] if len(fields) == 6 else ''))
    return period, leaves, depths, sorted(mappings, key=lambda m: m['start']), records

class Intervals:
    def __init__(self, entries):
        self.entries = sorted(entries)
        self.starts = [entry[0] for entry in self.entries]
        self.maximum_ends = []
        maximum = 0
        for _, end, _ in self.entries:
            maximum = max(maximum, end)
            self.maximum_ends.append(maximum)

    def find(self, address):
        index = bisect.bisect_right(self.starts, address) - 1
        found = []
        while index >= 0 and self.maximum_ends[index] > address:
            start, end, name = self.entries[index]
            if start <= address < end:
                found.append((end - start, name))
            index -= 1
        return found

class Elf:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:6] != b'\x7fELF\x02\x01':
            raise ValueError('Not a little-endian ELF64 image')
        phoff = struct.unpack_from('<Q', self.data, 32)[0]
        phsize, phcount = struct.unpack_from('<2H', self.data, 54)
        self.loads = []
        for index in range(phcount):
            entry = struct.unpack_from('<II6Q', self.data, phoff + index * phsize)
            if entry[0] == 1:
                self.loads.append(dict(flags=entry[1], offset=entry[2], address=entry[3], size=entry[5]))
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        shsize, shcount, shnames = struct.unpack_from('<3H', self.data, 58)
        self.sections = [struct.unpack_from('<II4QII2Q', self.data, shoff + index * shsize) for index in range(shcount)]
        names = self.sections[shnames]
        section_names = self.data[names[4]:names[4] + names[5]]
        self.has_debug = any(self.string(section_names, section[0]) == '.debug_info' for section in self.sections)
        functions = []
        for section in self.sections:
            if section[1] not in (2, 11):
                continue
            strings = self.sections[section[6]]
            table = self.data[strings[4]:strings[4] + strings[5]]
            for offset in range(section[4], section[4] + section[5], section[9]):
                name, info, other, shindex, value, size = struct.unpack_from('<IBBHQQ', self.data, offset)
                if info & 15 in (2, 10) and shindex != 0 and value and size:
                    functions.append((value, value + size, self.string(table, name)))
        self.functions = Intervals(functions)

    @staticmethod
    def string(table, offset):
        return table[offset:table.index(b'\0', offset)].decode('utf-8', errors='replace')

    def relative_pc(self, mapping, pc):
        for segment in self.loads:
            page_offset = segment['offset'] & ~4095
            page_address = segment['address'] & ~4095
            if (segment['flags'] & 1 and page_offset <= mapping['offset']
                    < (segment['offset'] + segment['size'] + 4095) & ~4095):
                return pc - mapping['start'] + page_address + mapping['offset'] - page_offset
        raise ValueError('No executable ELF load segment matches mapping')

def elf(path):
    path = Path(path)
    if path not in ELF_CACHE:
        try:
            ELF_CACHE[path] = Elf(path)
        except (OSError, ValueError, IndexError, struct.error):
            ELF_CACHE[path] = None
    return ELF_CACHE[path]

def build_id(path):
    result = subprocess.run(['readelf', '-n', str(path)], capture_output=True, text=True, check=True)
    match = re.search(r'Build ID:\s*([0-9a-f]+)', result.stdout)
    return match[1] if match else None

def resolve(profile_path, jit_path, output_path):
    period, leaves, depths, mappings, records = read_profile(profile_path)
    starts = [mapping['start'] for mapping in mappings]
    jit_entries = []
    if jit_path is not None:
        for line in jit_path.read_text().splitlines():
            fields = line.split(maxsplit=2)
            if len(fields) == 3:
                start, size = int(fields[0], 16), int(fields[1], 16)
                jit_entries.append((start, start + size, fields[2]))
    jit = Intervals(jit_entries)
    rows = []
    native = defaultdict(list)
    symbol_files = {}
    symbol_selection = {}
    addresses = Counter(leaves)
    for count, stack in records:
        for pc in stack[1:]:
            # x64 caller entries are return PCs. Attribute their lookup to the preceding instruction.
            addresses.setdefault(pc - 1 if pc else 0, 0)
    for pc, count in sorted(addresses.items()):
        matches = jit.find(pc)
        if matches:
            methods = [(size, name) for size, name in matches if not name.startswith('stub ')]
            if methods:
                # Reused/shared method ranges of different sizes are still ambiguous without sample timestamps.
                names = sorted({name for size, name in methods})
                kind = 'managed-jit' if len(names) == 1 else 'managed-jit-ambiguous'
                resolution = 'same-run JIT method interval' if len(names) == 1 else 'ambiguous same-run method ranges'
            else:
                smallest = min(size for size, name in matches)
                names = sorted({name for size, name in matches if size == smallest})
                kind, resolution = 'runtime-generated-stub', 'same-run runtime stub range (possibly coarse)'
            rows.append(dict(pc=hex(pc), count=count, kind=kind, module='[same-run JIT map]',
                             function=' | '.join(names), resolution=resolution, matching_range_count=len(matches)))
            continue
        index = bisect.bisect_right(starts, pc) - 1
        mapping = mappings[index] if index >= 0 and pc < mappings[index]['end'] else None
        path = mapping['path'] if mapping is not None else ''
        row = dict(pc=hex(pc), count=count, kind='unresolved', module=path or '[unmapped]',
                   function='<unresolved>', resolution='no exact symbol')
        rows.append(row)
        if path.endswith('.dll'):
            row['kind'] = 'managed-image-unresolved'
            continue
        image = elf(path) if path.startswith('/') else None
        if image is None or mapping is None:
            continue
        try:
            relative = image.relative_pc(mapping, pc)
        except ValueError:
            continue
        row.update(kind='native', relative_pc=hex(relative))
        if path not in symbol_selection:
            debug = ROOT/'native-symbols'/(Path(path).name + '.dbg')
            symbol_path = Path(path)
            if debug.exists():
                if build_id(debug) != build_id(path):
                    raise ValueError('Debug symbol build ID mismatch')
                symbol_path = debug
            symbol_selection[path] = symbol_path
            symbol_files[str(symbol_path)] = dict(build_id=build_id(symbol_path), sha256=hashlib.sha256(symbol_path.read_bytes()).hexdigest())
        symbol_path = symbol_selection[path]
        symbols = elf(symbol_path)
        if symbols is not None and symbols.functions.find(relative):
            native[symbol_path].append((relative, row))
    for symbol_path, entries in native.items():
        addresses = ''.join(hex(address) + '\n' for address, row in entries)
        result = subprocess.run(['addr2line', '-f', '-C', '-e', str(symbol_path)], input=addresses,
                                capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        if len(lines) != len(entries) * 2:
            raise ValueError('Unexpected addr2line record count')
        symbols = elf(symbol_path)
        bounded_names = sorted({name for address, row in entries for size, name in symbols.functions.find(address)})
        demangled = subprocess.run(['c++filt'], input=''.join(name + '\n' for name in bounded_names),
                                   capture_output=True, text=True, check=True).stdout.splitlines()
        if len(demangled) != len(bounded_names):
            raise ValueError('Unexpected demangled symbol count')
        demangled = dict(zip(bounded_names, demangled))
        for index, (address, row) in enumerate(entries):
            name, source = lines[index * 2:index * 2 + 2]
            ranges = symbols.functions.find(address)
            if not ranges:
                continue
            if symbols.has_debug and name != '??' and re.search(r':[1-9][0-9]*(?:\s|$)', source):
                row.update(function=name, source=source, resolution='DWARF line within sized ELF function')
            else:
                # Derive the actual bounded symbol identity, never a nearest-export fallback from addr2line.
                smallest = min(size for size, symbol in ranges)
                names = sorted({demangled[symbol] for size, symbol in ranges if size == smallest})
                row.update(function=' | '.join(names), resolution='sized ELF function interval')
    total = sum(leaves.values())
    functions, modules, kinds = Counter(), Counter(), Counter()
    for row in rows:
        if row['count'] == 0:
            continue
        functions[(row['module'], row['function'], row['resolution'])] += row['count']
        modules[row['module']] += row['count']
        kinds[row['kind']] += row['count']
    assert sum(functions.values()) == sum(modules.values()) == sum(kinds.values()) == total
    by_pc = {int(row['pc'], 16): row for row in rows}
    contexts = Counter()
    for count, stack in records:
        frames = [by_pc[stack[0]]] + [by_pc[pc - 1 if pc else 0] for pc in stack[1:]]
        contexts[tuple((row['module'], row['function'], row['resolution']) for row in frames[:16])] += count
    report = dict(profile=str(profile_path), profile_sha256=hashlib.sha256(profile_path.read_bytes()).hexdigest(),
        total_samples=total, sampling_period_microseconds=period, sampled_cpu_seconds=total * period / 1e6,
        named_leaf_samples=sum(row['count'] for row in rows if row['function'] != '<unresolved>'),
        unambiguous_named_leaf_samples=sum(row['count'] for row in rows if row['function'] != '<unresolved>'
                                           and row['kind'] not in ('managed-jit-ambiguous','runtime-generated-stub')),
        analysis_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        caveats=['Leaf interrupted PCs only; no unvalidated cumulative callgraph attribution.',
                 'CPU timers charge user+system time but do not reveal kernel function stacks.',
                 'Unresolved and ambiguous samples remain in the full denominator.',
                 'Same-run JIT intervals at stop lack per-sample timestamps; aliases/overlaps require review.',
                 'Context prefixes are sampled stack evidence, not call counts or validated complete managed callgraphs; caller PCs adjusted by minus1.'],
        depth_histogram=dict(depths), symbol_files=symbol_files,
        kinds=dict(kinds), modules=dict(modules),
        functions=[dict(module=module, function=function, resolution=resolution, samples=count,
                        percentage=100 * count / total if total else 0)
                   for (module, function, resolution), count in functions.most_common()],
        contexts=[dict(samples=count, percentage=100 * count / total if total else 0,
                       frames=[dict(module=module, function=function, resolution=resolution) for module,function,resolution in frames])
                  for frames,count in contexts.most_common(120)],
        leaves=[row for row in rows if row['count'] != 0])
    output_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(profile=profile_path.name, samples=total, sampled_cpu_seconds=report['sampled_cpu_seconds'],
                          named_leaf_samples=report['named_leaf_samples'], kinds=report['kinds'])))

if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('Usage: resolve_profile.py profile same-run-perf.map-or-dash output.json')
    resolve(Path(sys.argv[1]), None if sys.argv[2] == '-' else Path(sys.argv[2]), Path(sys.argv[3]))
