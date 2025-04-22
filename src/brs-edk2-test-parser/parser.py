#!/usr/bin/env python3
# SCT log parser

import sys
import argparse
import csv
import logging
import json
import re
import hashlib
import os
import curses
import time
import subprocess
from typing import Any, IO, Optional, cast, TypedDict, Callable
import yaml

try:
    from packaging import version
except ImportError:
    print('No packaging. You should install python3-packaging...')

try:
    from junit_xml import TestSuite, TestCase
except ImportError:
    print(
        'No junit_xml. You should install junit_xml for junit output'
        ' support...')

Dumper: Any

try:
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import Dumper

DbEntry = dict[str, str]
DbType = list[DbEntry]

class ConfigEntry(TypedDict):
    rule: str
    criteria: DbEntry
    update: DbEntry

ConfigType = list[ConfigEntry]
MetaData = dict[str, str]

class SeqFile(TypedDict):
    sha256: str
    name: str
    config: str

class SeqDb(TypedDict):
    seq_db: None
    seq_files: list[SeqFile]

BinsType = dict[str, list[dict[str, str]]]

# Not all yaml versions have a Loader argument.
if 'packaging.version' in sys.modules and \
   version.parse(yaml.__version__) >= version.parse('5.1'):
    yaml_load_args = {'Loader': yaml.FullLoader}
else:
    yaml_load_args = {}

# Colors
normal = ''
red = ''
yellow = ''
green = ''

if os.isatty(sys.stdout.fileno()):
    try:
        curses.setupterm()
        setafb = curses.tigetstr('setaf') or bytes()
        setaf = setafb.decode()
        tmp = curses.tigetstr('sgr0')
        normal = tmp.decode() if tmp is not None else ''
        red = curses.tparm(setafb, curses.COLOR_RED).decode() or ''
        yellow = curses.tparm(setafb, curses.COLOR_YELLOW).decode() or ''
        green = curses.tparm(setafb, curses.COLOR_GREEN).decode() or ''
    except Exception:
        pass

# Compute the plural of a word.
def maybe_plural(n: int, word: str) -> str:
    if n < 2:
        return word

    ll = word[len(word) - 1].lower()

    if ll in ('d', 's'):
        return word

    return f'{word}s'

# based loosely on https://stackoverflow.com/a/4391978
# returns a filtered list of dicts that meet some Key-value pair.
# I.E. key="result" value="FAILURE"
def key_value_find(
        list_1: list[dict[str, str]], key: str, value: str
        ) -> list[dict[str, str]]:

    found = []
    for test in list_1:
        if test[key] == value:
            found.append(test)
    return found

# Were we interpret test logs into test dicts
def test_parser(string: list[str], current: dict[str, str]) -> dict[str, str]:
    try:
        if len(string) < 3:
            logging.warning(f"Insufficient fields in test_parser: {string}, using defaults...")
            return {
                "name": "Unknown",
                "result": "UNKNOWN",
                **current,
                "guid": string[0] if len(string) > 0 else "",
                "log": ' '.join(string[1:]) if len(string) > 1 else ""
            }
        test_list = {
            "name": string[2] if len(string) > 2 else "Unknown",
            "result": string[1] if len(string) > 1 else "UNKNOWN",
            **current,
            "guid": string[0] if len(string) > 0 else "",
            "log": ' '.join(string[3:]) if len(string) > 3 else ""
        }
        return test_list
    except IndexError as e:
        logging.error(f"Index error in test_parser: {string} - Error: {str(e)}")
        return {
            "name": "Corrupted",
            "result": "UNKNOWN",
            **current,
            "guid": string[0] if len(string) > 0 else "",
            "log": ' '.join(string) if string else "Corrupted line"
        }

# Parse .ekl file to generate a list of test records
def ekl_parser(file: list[str]) -> list[dict[str, str]]:
    temp_list = []
    current: dict[str, str] = {}
    n = 0
    s = 0
    last_test = None
    result_pattern = re.compile(r'\b(PASS|FAILURE|SKIPPED|WARNING|SPURIOUS|IGNORED|DROPPED)\b')

    for i, line in enumerate(file):
        line = line.rstrip()
        if line == '':
            continue

        split_line = line.split('|')

        if len(split_line) >= 2 and split_line[0] == '' and split_line[1] == "TERM":
            if not n:
                logging.debug(f"Skipped test set `{current.get('sub set', '')}'")
                temp_list.append({
                    **current,
                    'name': '',
                    'guid': '',
                    'log': '',
                    'result': 'SKIPPED',
                })
                s += 1
            current = {}
            n = 0
            last_test = None
            continue

        if len(split_line) >= 2 and split_line[0] == '' and split_line[1] == "HEAD":
            try:
                group, Set = split_line[12].split('\\')
            except Exception:
                group, Set = '', split_line[12]
            current = {
                'group': group,
                'test set': Set,
                'sub set': split_line[10],
                'set guid': split_line[8],
                'iteration': split_line[4],
                'start date': split_line[6],
                'start time': split_line[7],
                'revision': split_line[9],
                'descr': split_line[11],
                'device path': '|'.join(split_line[13:]),
            }
            continue

        if split_line[0] != '' and split_line[0][0] != " ":
            try:
                split_test = [new_string for old_string in split_line
                             for new_string in old_string.split(':')]
                tmp_dict = test_parser(split_test, current)
                temp_list.append(tmp_dict)
                n += 1
                last_test = tmp_dict
            except Exception as e:
                logging.error(f"Line {i+1}: {split_line} - Error: {str(e)}")
                logging.warning(f"Skipping corrupted line {i+1}: {line}")
                continue
            continue

        result_match = result_pattern.search(line)
        if result_match:
            result = result_match.group(1)
            tmp_dict = {
                **current,
                'guid': current.get('set guid', ''),
                'name': 'Debug_Test_' + str(i + 1),
                'result': result,
                'log': line
            }
            temp_list.append(tmp_dict)
            n += 1
            last_test = tmp_dict
            logging.debug(f"Parsed non-standard test at line {i+1}: result={result}, line=`{line}'")
        else:
            logging.debug(f"Ignored non-test line {i+1}: `{line}'")
            if last_test is not None:
                last_test['log'] += f"\n{line}"
            else:
                logging.debug(f"No prior test to append line {i+1}: `{line}'")

    if s:
        logging.debug(f'{s} skipped test set(s)')

    return temp_list

# Parse Seq file, used to tell which tests should run.
def seq_parser(file: IO[str]) -> list[dict[str, str]]:
    temp = []
    lines = file.readlines()
    magic = 7
    if len(lines) % magic != 0:
        logging.error(f"{red}seqfile cut short{normal}, should be mod7")
        sys.exit(1)
    for x in range(0, len(lines), magic):
        if "0xFFFFFFFF" not in lines[x + 5]:
            seq_dict = {
                "name": lines[x + 3][5:-1],
                "guid": lines[x + 2][5:-1],
                "Iteration": lines[x + 5][11:-1],
                "rev": lines[x + 1][9:-1],
                "Order": lines[x + 4][6:-1]
            }
            temp.append(seq_dict)

    return temp

# Print items by "group"
def key_tree_2_md(input_list: list[dict[str, str]], file: IO[str]) -> None:
    h: dict[str, list[dict[str, str]]] = {}
    for t in input_list:
        g = t['group']
        if g not in h:
            h[g] = []
        h[g].append(t)
    for g in sorted(h.keys()):
        file.write("### " + g)
        dict_2_md(h[g], file)

# generic writer, takes a list of dicts and turns the dicts into an MD table.
def dict_2_md(input_list: list[dict[str, str]], file: IO[str]) -> None:
    if len(input_list) > 0:
        file.write("\n\n")
        k = input_list[0].keys()
        temp_string1, temp_string2 = "|", "|"
        for x in k:
            temp_string1 += (x + "|")
            temp_string2 += ("---|")
        file.write(temp_string1 + "\n" + temp_string2 + "\n")
        for w in input_list:
            test_string = "|"
            for y in k:
                v = w[y] if y in w else ''
                test_string += v + "|"
            file.write(test_string + '\n')
    file.write("\n\n")

# Sanitize our YAML configuration
def sanitize_yaml(conf: ConfigType) -> None:
    rules = set()
    for i, r in enumerate(conf):
        if 'rule' not in r:
            r['rule'] = f'r{i}'
            logging.debug(f"Auto-naming rule {i} `{r['rule']}'")
            conf[i] = r
        if r['rule'] in rules:
            logging.warning(f"{yellow}Duplicate rule{normal} {i} `{r['rule']}'")
        rules.add(r['rule'])
        if 'criteria' not in r or not isinstance(r['criteria'], dict) or \
           'update' not in r or not isinstance(r['update'], dict):
            logging.error(f"{red}Bad rule{normal} {i} `{r}'")
            raise Exception()

def matches_crit(test: DbEntry, crit: DbEntry) -> bool:
    for key, value in crit.items():
        if key not in test or test[key].find(value) < 0:
            return False
    return True

def apply_rules(cross_check: DbType, conf: ConfigType) -> None:
    stats = {}
    for r in conf:
        stats[r['rule']] = 0
    s = len(cross_check)
    for i in range(s):
        test = cross_check[i]
        for r in conf:
            if not matches_crit(test, r['criteria']):
                continue
            rule = r['rule']
            logging.debug(f"Applying rule `{rule}' to test {i} `{test['name']}'")
            test.update({
                **r['update'],
                'Updated by': rule,
            })
            stats[rule] += 1
            break
    n = 0
    for rule, cnt in stats.items():
        logging.debug(f"{cnt} matche(s) for rule `{rule}'")
        n += cnt
    if n:
        x = len(conf)
        logging.info(f"Updated {n} {maybe_plural(n, 'test')} out of {s} after applying {x} {maybe_plural(x, 'rule')}")

def load_config(filename: str) -> ConfigType:
    logging.debug(f'Read {filename}')
    with open(filename, 'r') as yamlfile:
        y = yaml.load(yamlfile, **yaml_load_args)
        conf = cast(Optional[ConfigType], y)
    if conf is None:
        conf = []
    logging.debug(f"{len(conf)} rule(s)")
    sanitize_yaml(conf)
    return conf

def filter_data(cross_check: DbType, Filter: str) -> DbType:
    logging.debug(f"Filtering with `{Filter}'")
    before = len(cross_check)
    def function(x: DbEntry) -> bool:
        return bool(eval(Filter))
    r = list(filter(function, cross_check))
    after = len(r)
    n = before - after
    logging.info(f"Filtered out {n} {maybe_plural(n, 'test')}, kept {after}")
    return r

def sort_data(cross_check: DbType, sort_keys: str) -> None:
    logging.debug(f"Sorting on `{sort_keys}'")
    def key_func(k: str) -> Callable[[dict[str, str]], str]:
        def func(x: dict[str, str]) -> str:
            return x[k]
        return func
    for k in reversed(sort_keys.split(',')):
        cross_check.sort(key=key_func(k))

def keep_fields(cross_check: DbType, fields: str) -> None:
    logging.debug(f"Keeping fields: `{fields}'")
    s = set(fields.split(','))
    for x in cross_check:
        for k in list(x.keys()):
            if k not in s:
                del x[k]

def uniq(cross_check: DbType) -> DbType:
    logging.debug("Collapsing duplicates")
    h: dict[str, DbEntry] = {}
    for x in cross_check:
        i = ''
        for k in sorted(x.keys()):
            i += f"{k}:{x[k]} "
        if i not in h:
            h[i] = {
                'count': '0',
                **x,
            }
        h[i]['count'] = str(int(h[i]['count']) + 1)
    r = list(h.values())
    logging.info(f"{len(r)} unique entries")
    return r

def discover_fields(cross_check: DbType, fields: Optional[str] = None) -> list[str]:
    if fields is not None:
        keys = fields.split(',')
    else:
        keys = []
    s: set[str] = set()
    for x in cross_check:
        s = s.union(x.keys())
    s = s.difference(keys)
    keys += sorted(s)
    logging.debug(f'Fields: {keys}')
    return keys

def gen_csv(cross_check: DbType, filename: str, fields: list[str]) -> None:
    logging.debug(f'Generate {filename} (fields: {fields})')
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields, delimiter=';')
        writer.writeheader()
        writer.writerows(cross_check)

def gen_json(cross_check: DbType, filename: str) -> None:
    logging.debug(f'Generate {filename}')
    with open(filename, 'w') as jsonfile:
        json.dump(cross_check, jsonfile, sort_keys=True, indent=2)

def gen_junit(cross_check: DbType, filename: str) -> None:
    assert 'junit_xml' in sys.modules
    logging.debug(f'Generate {filename}')
    testsuites = {}
    for result in cross_check:
        testcase = TestCase(
            result['name'] if result['name'] else result['sub set'],
            (result['test set'] if result['test set'] else result['set guid']) + "." + result['sub set'],
            0,
            "Description: " + result['descr'] +
            "\nSet GUID: " + result['set guid'] +
            "\nGUID: " + result['guid'] +
            "\nDevice Path: " + result['device path'] +
            "\nStart Date: " + result['start date'] +
            "\nStart Time: " + result['start time'] +
            "\nRevision: " + result['revision'] +
            "\nIteration: " + result['iteration'] +
            "\nLog: " + result['log'],
            "")
        match result['result']:
            case 'FAILURE':
                testcase.add_failure_info(result['result'])
            case 'SKIPPED':
                testcase.add_skipped_info(result['result'])
            case 'DROPPED':
                testcase.add_skipped_info(result['result'])
        group = result['group'] if result['group'] else result['test set']
        if group not in testsuites:
            testsuites[group] = TestSuite(group)
        testsuites[group].test_cases.append(testcase)
    with open(filename, 'w') as file:
        TestSuite.to_file(file, testsuites.values())

def yaml_meta(f: IO[str], meta: MetaData) -> None:
    print('# Meta-data:', file=f)
    for k in sorted(meta.keys()):
        print(f"# {k}: {meta[k]}", file=f)
    print('', file=f)

def gen_yaml(cross_check: DbType, filename: str, meta: MetaData) -> None:
    logging.debug(f'Generate {filename}')
    with open(filename, 'w') as yamlfile:
        yaml_meta(yamlfile, meta)
        yaml.dump(cross_check, yamlfile, Dumper=Dumper)

def gen_template(cross_check: DbType, filename: str, meta: MetaData) -> None:
    logging.debug(f'Generate {filename}')
    omitted_keys = set(['iteration', 'start date', 'start time'])
    t = []
    i = 1
    for x in cross_check:
        if x['result'] == 'PASS':
            continue
        r: ConfigEntry = {
            'rule': f'Generated rule ({i})',
            'criteria': {},
            'update': {'result': 'TEMPLATE'},
        }
        for key, value in x.items():
            if key in omitted_keys:
                continue
            if key == 'log':
                value = re.sub(r'^/.*/', '', str(value))
            r['criteria'][key] = value
        t.append(r)
        i += 1
    with open(filename, 'w') as yamlfile:
        yaml_meta(yamlfile, meta)
        yaml.dump(t, yamlfile, Dumper=Dumper)

def do_print(cross_check: DbType, fields: list[str]) -> None:
    logging.debug(f'Print (fields: {fields})')
    w = {}
    for f in fields:
        w[f] = len(f)
    for x in cross_check:
        for f in fields:
            w[f] = max(w[f], len(str(x[f]) if f in x else ''))
    fm1 = fields[:len(fields) - 1]
    lf = fields[len(fields) - 1]
    sep = '  '
    print(sep.join([*map(lambda f: f"{f.capitalize():{w[f]}}", fm1), lf.capitalize()]))
    print(sep.join([*map(lambda f: '-' * w[f], fields)]))
    def map_func(x: dict[str, str]) -> Callable[[str], str]:
        def func(f: str) -> str:
            return f"{x[f] if f in x else '':{w[f]}}"
        return func
    for x in cross_check:
        print(sep.join([*map(map_func(x), fm1), x[lf] if lf in x else '']))

def combine_dbs(db1: DbType, db2: DbType) -> DbType:
    cross_check = db1
    s = set()
    for x in db2:
        s.add(x['guid'])
    n = 0
    for i, x in enumerate(cross_check):
        if x['set guid'] not in s:
            logging.debug(f"Spurious test {i} `{cross_check[i]['name']}'")
            x['result'] = 'SPURIOUS'
            n += 1
    if n:
        logging.debug(f'{n} spurious test(s)')
    s = set()
    for x in cross_check:
        s.add(x['set guid'])
    n = 0
    for i, x in enumerate(db2):
        if not x['guid'] in s:
            logging.debug(f"Dropped test set {i} `{x['name']}'")
            cross_check.append({
                'descr': '',
                'device path': '',
                'guid': '',
                'iteration': '',
                'log': '',
                'name': '',
                'start date': '',
                'start time': '',
                'test set': '',
                'sub set': x['name'],
                'set guid': x['guid'],
                'revision': x['rev'],
                'group': 'Unknown',
                'result': 'DROPPED',
            })
            n += 1
    if n:
        logging.debug(f'{n} dropped test set(s)')
    return cross_check

def sanity_check_seq_db(seq_db: SeqDb) -> None:
    assert 'seq_db' in seq_db
    s = set()
    for x in seq_db['seq_files']:
        sha = x['sha256']
        assert sha not in s
        s.add(sha)

def load_seq_db(filename: str) -> SeqDb:
    logging.debug(f'Read {filename}')
    with open(filename, 'r') as yamlfile:
        y = yaml.load(yamlfile, **yaml_load_args)
        seq_db = cast(Optional[SeqDb], y)
    if seq_db is None:
        seq_db = {'seq_db': None, 'seq_files': []}
    sanity_check_seq_db(seq_db)
    logging.debug(f"{len(seq_db['seq_files'])} known seq file(s)")
    return seq_db

def ident_seq(seq_file: str, seq_db_name: str) -> Optional[SeqFile]:
    seq_db = load_seq_db(seq_db_name)
    hm = 'sha256'
    hl = hashlib.new(hm)
    with open(seq_file, 'rb') as f:
        hl.update(f.read())
    h = hl.hexdigest()
    logging.debug(f'{hm} {h} {seq_file}')
    for x in seq_db['seq_files']:
        if x['sha256'] == h:
            logging.info(f"""{green}Identified{normal} `{seq_file}' as "{x['name']}".""")
            if 'deprecated' in x:
                logging.warning(f"{yellow}This sequence file is deprecated!{normal}")
            return x
    logging.warning(f"{yellow}Could not identify{normal} `{seq_file}'...")
    return None

def read_log_and_seq(log_file: str, seq_file: str) -> DbType:
    logging.debug(f'Read {log_file}')
    with open(log_file, "r", encoding="utf-16") as f:
        db1 = ekl_parser(f.readlines())
    logging.debug(f"{len(db1)} test(s)")
    logging.debug(f'Read {seq_file}')
    with open(seq_file, "r", encoding="utf-16") as f:
        db2 = seq_parser(f)
    logging.debug(f"{len(db2)} test set(s)")
    return combine_dbs(db1, db2)

def gen_md(md: str, res_keys: set[str], bins: BinsType, meta: MetaData) -> None:
    logging.debug(f'Generate {md}')
    with open(md, 'w') as resultfile:
        resultfile.write("# SCT Summary\n\n")
        resultfile.write("|Result|Test(s)|\n")
        resultfile.write("|--|--|\n")
        for k in sorted(res_keys):
            resultfile.write(f"|{k.title()}:|{len(bins[k])}|\n")
        resultfile.write("\n\n")
        n = 1
        res_keys_np = set(res_keys)
        res_keys_np.remove('PASS')
        for k in sorted(res_keys_np):
            resultfile.write(f"## {n}. {k.title()} by group\n\n")
            key_tree_2_md(bins[k], resultfile)
            n += 1
        resultfile.write('## Meta-data\n\n')
        resultfile.write("|  |  |\n")
        resultfile.write("|--|--|\n")
        for k in sorted(meta.keys()):
            resultfile.write(f"|{k}:|{meta[k]}|\n")

def read_md(input_md: str) -> DbType:
    logging.debug(f'Read {input_md}')
    tables = []
    with open(input_md, 'r') as f:
        t: Optional[list[list[str]]] = None
        for i, line in enumerate(f):
            line = line.rstrip()
            if re.match(r'^\|', line):
                line = re.sub(r'\((\w+)\|(\w+)\)', r'(\1%\2)', line)
                x = line.split('|')
                x = x[1:len(x) - 1]
                x = [re.sub(r'%', '|', e) for e in x]
                if t is None:
                    t = []
                    logging.debug(f'Table line {i + 1}, keys: {x}')
                t.append(x)
            elif t is not None:
                tables.append(t)
                t = None
        if t is not None:
            tables.append(t)
    tables2 = filter(lambda x: len(x[0]) > 2, tables)
    cross_check = []
    for t in tables2:
        keys = t.pop(0)
        n = len(keys)
        t.pop(0)
        for i, x in enumerate(t):
            assert len(x) == n
            y = {}
            for j, k in enumerate(keys):
                y[k] = x[j]
            cross_check.append(y)
    return cross_check

def print_summary(bins: BinsType, res_keys: set[str]) -> None:
    colors = {
        'DROPPED': red,
        'FAILURE': red,
        'PASS': green,
        'SKIPPED': yellow,
        'WARNING': yellow,
    }
    d = {}
    for k in res_keys:
        n = len(bins[k])
        d[k] = f'{n} {maybe_plural(n, k.lower())}'
        if n > 0 and k in colors:
            d[k] = f'{colors[k]}{d[k]}{normal}'
    logging.info(', '.join(map(lambda k: d[k], sorted(res_keys))))

def meta_data(argv: list[str], here: str) -> MetaData:
    r: MetaData = {
        'command-line': ' '.join(argv),
        'date': f"{time.asctime(time.gmtime())} UTC",
    }
    cp = subprocess.run(
        f"git -C '{here}' describe --always --abbrev=12 --dirty", shell=True,
        capture_output=True, check=False)
    logging.debug(cp)
    if cp.returncode:
        logging.debug('No git')
    else:
        r['git-commit'] = cp.stdout.decode().rstrip()
    logging.debug(f"meta-data: {r}")
    return r

def sanity_check(cross_check: DbType) -> None:
    fields = [
        'descr',
        'device path',
        'guid',
        'iteration',
        'log',
        'name',
        'start date',
        'start time',
        'test set',
        'sub set',
        'set guid',
        'revision',
        'group',
        'result',
    ]
    for x in cross_check:
        for f in fields:
            assert f in x

if __name__ == '__main__':
    me = os.path.realpath(__file__)
    here = os.path.dirname(me)
    parser = argparse.ArgumentParser(
        description='Process SCT results.'
                    ' This program takes the SCT summary and sequence files,'
                    ' and generates a nice report in markdown format.',
        epilog='When sorting is requested, tests data are sorted'
               ' according to the first sort key, then the second, etc.'
               ' Sorting happens after update by the configuration rules.'
               ' Useful example: --sort'
               ' "group,descr,set guid,test set,sub set,guid,name,log"'
               ' When not validating a configuration file, an input .ekl and'
               ' an input .seq files are required.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--csv', help='Output .csv filename')
    parser.add_argument('--json', help='Output .json filename')
    if 'junit_xml' in sys.modules:
        parser.add_argument('--junit', help='Output .junit filename')
    parser.add_argument('--md', help='Output .md filename', default='result.md')
    parser.add_argument('--debug', action='store_true', help='Turn on debug messages')
    parser.add_argument('--sort', help='Comma-separated list of keys to sort output on')
    parser.add_argument('--filter', help='Python expression to filter results')
    parser.add_argument('--fields', help='Comma-separated list of fields to write')
    parser.add_argument('--uniq', action='store_true', help='Collapse duplicates')
    parser.add_argument('--print', action='store_true', help='Print results to stdout')
    parser.add_argument('--print-meta', action='store_true', help='Print meta-data to stdout')
    parser.add_argument('--input-md', help='Input .md filename')
    parser.add_argument('--seq-db', help='Known sequence files database filename', default=f'{here}/seq_db.yaml')
    parser.add_argument('log_file', nargs='?', help='Input .ekl filename')
    parser.add_argument('seq_file', nargs='?', help='Input .seq filename')
    parser.add_argument('find_key', nargs='?', help='Search key')
    parser.add_argument('find_value', nargs='?', help='Search value')
    parser.add_argument('--config', help='Input .yaml configuration filename')
    parser.add_argument('--yaml', help='Output .yaml filename')
    parser.add_argument('--template', help='Output .yaml config template filename')
    args = parser.parse_args()

    logging.basicConfig(
        format='%(levelname)s %(funcName)s: %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO)

    ln = logging.getLevelName(logging.WARNING)
    logging.addLevelName(logging.WARNING, f"{yellow}{ln}{normal}")
    ln = logging.getLevelName(logging.ERROR)
    logging.addLevelName(logging.ERROR, f"{red}{ln}{normal}")

    if args.log_file is None:
        logging.error("No input .ekl!")
        sys.exit(1)
    if args.seq_file is None:
        logging.error("No input .seq!")
        sys.exit(1)

    if args.config is not None:
        config = args.config
    else:
        config = f'{here}/EBBR.yaml'

    meta = meta_data(sys.argv, here)

    if args.input_md is not None:
        cross_check = read_md(args.input_md)
        ident = None
    else:
        ident = ident_seq(args.seq_file, args.seq_db)
        if ident is not None:
            meta['seq-file-ident'] = ident['name']
        cross_check = read_log_and_seq(args.log_file, args.seq_file)

    logging.debug(f"{len(cross_check)} combined test(s)")

    sanity_check(cross_check)

    if args.config is None and ident is not None:
        config = f"{here}/{ident['config']}"

    logging.debug(f"Read config `{config}'")
    conf = load_config(config)
    apply_rules(cross_check, conf)

    if args.filter is not None:
        cross_check = filter_data(cross_check, args.filter)

    if args.sort is not None:
        sort_data(cross_check, args.sort)

    res_keys = set(['DROPPED', 'FAILURE', 'WARNING', 'PASS'])
    for x in cross_check:
        res_keys.add(x['result'])

    bins = {}
    for k in res_keys:
        bins[k] = key_value_find(cross_check, "result", k)

    print_summary(bins, res_keys)

    if args.print_meta:
        print()
        print('meta-data')
        print('---------')
        for k in sorted(meta.keys()):
            print(f"{k}: {meta[k]}")

    if args.input_md is None or args.input_md != args.md:
        gen_md(args.md, res_keys, bins, meta)

    if args.template is not None:
        gen_template(cross_check, args.template, meta)

    if args.fields is not None:
        keep_fields(cross_check, args.fields)

    if args.uniq:
        cross_check = uniq(cross_check)

    fields = discover_fields(cross_check, args.fields)

    if args.csv is not None:
        gen_csv(cross_check, args.csv, fields)

    if args.json is not None:
        gen_json(cross_check, args.json)

    if 'junit' in args and args.junit is not None:
        gen_junit(cross_check, args.junit)

    if args.yaml is not None:
        gen_yaml(cross_check, args.yaml, meta)

    if args.print:
        do_print(cross_check, fields)

    if args.find_key is not None and args.find_value is not None:
        found = key_value_find(cross_check, args.find_key, args.find_value)
        print("found:", len(found), "items with search constraints")
        for x in found:
            print(x["guid"], ":", x["name"], "with", args.find_key, ":", x[args.find_key])