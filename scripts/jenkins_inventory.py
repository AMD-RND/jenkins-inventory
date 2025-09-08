#!/usr/bin/env python3
"""
jenkins_inventory.py
Collect node and running-build details from a Jenkins master via REST API.
Outputs JSON and CSV into an output directory.

Usage:
  python jenkins_inventory.py --url https://jenkins.example.com --user me --token mytoken --output ./output --concurrency 20 --deep
"""
import argparse
import requests
import os
import csv
import json
import logging
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

def get_crumb(session: requests.Session, base: str, verify: bool=True):
    """
    Request Jenkins crumb (if CSRF enabled). Returns header dict or {}.
    """
    url = base.rstrip('/') + '/crumbIssuer/api/json'
    try:
        r = session.get(url, verify=verify, timeout=15)
        if r.status_code == 200:
            data = r.json()
            field = data.get('crumbRequestField')
            crumb = data.get('crumb')
            if field and crumb:
                logging.info("Got crumb issuer")
                return {field: crumb}
        else:
            logging.debug("No crumb issuer or non-200: %s", r.status_code)
    except Exception as e:
        logging.debug("Crumb fetch failed: %s", e)
    return {}

def fetch_computers(session: requests.Session, base: str, verify: bool=True) -> Dict[str, Any]:
    """
    Fetch top-level /computer/api/json (all nodes). Use a 'tree' param to limit size but include monitorData[*].
    """
    api = base.rstrip('/') + '/computer/api/json'
    tree = ('computer[displayName,offline,temporarilyOffline,idle,numExecutors,'
            'executors[currentExecutable[url,fullDisplayName,number,building,estimatedDuration],progress],'
            'oneOffExecutors[currentExecutable[url,fullDisplayName,number,building],progress],'
            'monitorData[*]]')
    params = {'tree': tree}
    r = session.get(api, params=params, verify=verify, timeout=60)
    r.raise_for_status()
    return r.json()

def fetch_node_detail(session: requests.Session, base: str, node_name: str, verify: bool=True) -> Dict[str, Any]:
    """
    Fetch per-node detail: /computer/<node>/api/json with a tailored tree.
    """
    encoded = quote(node_name, safe='')
    api = f"{base.rstrip('/')}/computer/{encoded}/api/json"
    tree = ('displayName,executors[currentExecutable[url,fullDisplayName,number,building,estimatedDuration],progress],'
            'oneOffExecutors[currentExecutable[url,fullDisplayName,number,building],progress],'
            'assignedLabels[name],numExecutors,remoteFS,nodeDescription,monitorData[*],offline,offlineCause,offlineCauseReason,temporarilyOffline')
    params = {'tree': tree}
    r = session.get(api, params=params, verify=verify, timeout=30)
    r.raise_for_status()
    return r.json()

def flatten_monitor_data(monitor: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten monitorData dict into simple key -> value strings.
    monitorData keys often look like 'hudson.node_monitors.ArchitectureMonitor' etc.
    """
    out = {}
    if not isinstance(monitor, dict):
        return out
    for k, v in monitor.items():
        safe_k = k.replace('.', '_').replace('$', '_')
        if isinstance(v, dict):
            # flatten nested dict
            for subk, subv in v.items():
                subkey = f"monitor_{safe_k}_{subk}"
                try:
                    # convert primitive values; JSON-serialize complex objects
                    if isinstance(subv, (str, int, float, bool, type(None))):
                        out[subkey] = subv
                    else:
                        out[subkey] = json.dumps(subv)
                except Exception:
                    out[subkey] = str(subv)
        else:
            out[f"monitor_{safe_k}"] = json.dumps(v) if not isinstance(v, (str, int, float, bool, type(None))) else v
    return out

def extract_running_from_executors(executors_list: List[Dict[str,Any]]) -> List[Dict[str,Any]]:
    out = []
    for exe in executors_list or []:
        cur = exe.get('currentExecutable')
        if cur:
            out.append({
                'job_url': cur.get('url'),
                'job_name': cur.get('fullDisplayName'),
                'build_number': cur.get('number'),
                'building': cur.get('building', False),
                'estimatedDuration': cur.get('estimatedDuration'),
                'progress': exe.get('progress'),
            })
    return out

def write_json(path: str, data: Any):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def write_csv_dynamic(path: str, rows: List[Dict[str,Any]]):
    if not rows:
        # write empty file with message
        with open(path, 'w', encoding='utf-8') as f:
            f.write('')
        return
    # collect union of keys
    all_keys = set()
    for r in rows:
        all_keys.update(r.keys())
    fieldnames = sorted(all_keys)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            # ensure stringifiable values
            out = {k: (json.dumps(v) if isinstance(v, (dict, list)) else ('' if v is None else v)) for k,v in r.items()}
            writer.writerow(out)

def main():
    parser = argparse.ArgumentParser(description="Jenkins nodes inventory")
    parser.add_argument('--url', required=True, help='Jenkins base URL (e.g. https://jenkins.example.com)')
    parser.add_argument('--user', required=True, help='Jenkins username')
    parser.add_argument('--token', required=True, help='Jenkins API token or password')
    parser.add_argument('--output', default='./output', help='Output directory')
    parser.add_argument('--concurrency', type=int, default=10, help='Parallel threads for deep fetch')
    parser.add_argument('--deep', action='store_true', help='Fetch per-node detailed info (labels, remoteFS, etc.)')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification (not recommended)')
    args = parser.parse_args()

    verify = not args.insecure
    os.makedirs(args.output, exist_ok=True)

    s = requests.Session()
    s.auth = (args.user, args.token)
    s.headers.update({'Accept': 'application/json'})

    # crumb
    crumb = get_crumb(s, args.url, verify)
    if crumb:
        s.headers.update(crumb)

    # fetch computers
    logging.info("Fetching computers list from Jenkins...")
    top = fetch_computers(s, args.url, verify)
    write_json(os.path.join(args.output, 'raw_nodes.json'), top)

    computers = top.get('computer', [])
    logging.info("Found %d computers", len(computers))

    nodes_summary = []
    running_builds = []
    monitor_flat_list = []

    # If deep: fetch per-node details in parallel
    if args.deep:
        logging.info("Deep fetching per-node details with concurrency=%d", args.concurrency)
        with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futures = {ex.submit(fetch_node_detail, s, args.url, c.get('displayName') or c.get('displayName', ''), verify): c for c in computers}
            for fut in tqdm(as_completed(futures), total=len(futures), desc="nodes"):
                c0 = futures[fut]
                try:
                    node_data = fut.result()
                except Exception as e:
                    logging.warning("Per-node fetch failed for %s: %s", c0.get('displayName'), e)
                    node_data = c0  # fall back to top-level
                # flatten and process
                display = node_data.get('displayName') or c0.get('displayName')
                base_row = {
                    'displayName': display,
                    'idle': node_data.get('idle', c0.get('idle')),
                    'offline': node_data.get('offline', c0.get('offline')),
                    'temporarilyOffline': node_data.get('temporarilyOffline', c0.get('temporarilyOffline')),
                    'numExecutors': node_data.get('numExecutors', c0.get('numExecutors')),
                    'remoteFS': node_data.get('remoteFS'),
                    'nodeDescription': node_data.get('nodeDescription'),
                }

                # labels
                labels = node_data.get('assignedLabels') or []
                base_row['labels'] = ','.join([l.get('name','') for l in labels])

                # monitor flatten
                md = node_data.get('monitorData') or node_data.get('monitorData') or {}
                flat = flatten_monitor_data(md)
                merged = {**base_row, **flat}
                nodes_summary.append(merged)
                monitor_flat_list.append({'displayName': display, **flat})

                # running builds from executors and oneOffExecutors
                runs = extract_running_from_executors(node_data.get('executors', []))
                runs += extract_running_from_executors(node_data.get('oneOffExecutors', []))
                for r in runs:
                    r['node'] = display
                running_builds.extend(runs)

    else:
        logging.info("Processing top-level computer list (no deep per-node calls).")
        for c in computers:
            display = c.get('displayName')
            base_row = {
                'displayName': display,
                'idle': c.get('idle'),
                'offline': c.get('offline'),
                'temporarilyOffline': c.get('temporarilyOffline'),
                'numExecutors': c.get('numExecutors'),
            }
            md = c.get('monitorData') or {}
            flat = flatten_monitor_data(md)
            merged = {**base_row, **flat}
            nodes_summary.append(merged)
            monitor_flat_list.append({'displayName': display, **flat})
            runs = extract_running_from_executors(c.get('executors', []))
            runs += extract_running_from_executors(c.get('oneOffExecutors', []))
            for r in runs:
                r['node'] = display
            running_builds.extend(runs)

    # Write outputs
    write_json(os.path.join(args.output, 'nodes_monitor_flat.json'), monitor_flat_list)
    write_json(os.path.join(args.output, 'running_builds.json'), running_builds)
    write_json(os.path.join(args.output, 'nodes_summary.json'), nodes_summary)

    write_csv_dynamic(os.path.join(args.output, 'nodes_summary.csv'), nodes_summary)
    write_csv_dynamic(os.path.join(args.output, 'running_builds.csv'), running_builds)

    logging.info("Done. Outputs written to %s", os.path.abspath(args.output))


if __name__ == '__main__':
    main()
