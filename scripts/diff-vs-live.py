#!/usr/bin/env python3
# =============================================================================
# diff-vs-live.py — verify repo machine configs match the live cluster.
#
# Reads:
#   - cluster/config.env (CP_NODES, WORKER_NODES, KUBERNETES_VERSION)
#   - .s3/generated/{controlplane,worker}/<name>.yaml  (locally regenerated)
#   - <live-dump-dir>/<ip>.machineconfig-resource.yaml (one per node, from
#     `talosctl get machineconfig -o yaml`)
#   - --kube-version <vX.Y.Z>  (optional; from kubectl version --output=json)
#
# Compares:
#   - The v1alpha1 main config: every key recursively, including nested
#     dicts and lists.
#   - Multi-doc kinds (VolumeConfig, UserVolumeConfig, HostnameConfig,
#     etc.): presence + content equality, keyed by (kind, name).
#   - Kubernetes server gitVersion vs KUBERNETES_VERSION pin (exact match).
#
# Exits 0 on no drift, 1 on any drift, 2 on input errors.
#
# Implements the ADR-0003 §Confirmation §3 drift-detection requirement.
# =============================================================================

import argparse
import os
import re
import sys
import yaml


def load_generated(path):
    """Read the locally generated config (multi-doc YAML)."""
    with open(path) as f:
        return list(yaml.safe_load_all(f))


def load_live(path):
    """Parse a `talosctl get machineconfig -o yaml` dump.

    Outer document is a resource envelope: metadata + spec where spec is a
    string containing the actual machineconfig YAML (possibly multi-doc).
    """
    with open(path) as f:
        outer = list(yaml.safe_load_all(f))
    if not outer or 'spec' not in outer[0]:
        raise ValueError(f"{path}: unexpected machineconfig resource shape")
    return list(yaml.safe_load_all(outer[0]['spec']))


def deep_diff(a, b, path=''):
    """Yield (path, kind) tuples for every leaf-level difference between a and b."""
    if type(a) is not type(b):
        yield path, f'TYPE({type(a).__name__}->{type(b).__name__})'
        return
    if isinstance(a, dict):
        for k in sorted(set(a.keys()) | set(b.keys())):
            sub = f'{path}.{k}' if path else k
            if k not in a:
                yield sub, 'gen-extra'
            elif k not in b:
                yield sub, 'live-extra'
            else:
                yield from deep_diff(a[k], b[k], sub)
    elif isinstance(a, list):
        if a != b:
            yield path, 'list-diff'
    else:
        if a != b:
            yield path, 'val-diff'


def parse_inventory(config_env_path):
    """Return [(name, ip, role)] from cluster/config.env CP_NODES + WORKER_NODES."""
    nodes = []
    text = open(config_env_path).read()
    for var, role in (('CP_NODES', 'controlplane'), ('WORKER_NODES', 'worker')):
        m = re.search(rf'^{var}="([^"]+)"', text, re.MULTILINE)
        if not m:
            sys.exit(f'ERROR: {var} not found in {config_env_path}')
        for entry in m.group(1).split():
            name, ip = entry.split(':', 1)
            nodes.append((name, ip, role))
    if not nodes:
        sys.exit(f'ERROR: no nodes parsed from {config_env_path}')
    return nodes


def parse_kube_version(config_env_path):
    text = open(config_env_path).read()
    m = re.search(r'^KUBERNETES_VERSION="([^"]+)"', text, re.MULTILINE)
    if not m:
        sys.exit(f'ERROR: KUBERNETES_VERSION not found in {config_env_path}')
    return m.group(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('live_dump_dir',
                    help='Directory containing <ip>.machineconfig-resource.yaml files')
    ap.add_argument('--config-env', default='cluster/config.env')
    ap.add_argument('--generated-dir', default='.s3/generated')
    ap.add_argument('--kube-version',
                    help='Server gitVersion (e.g. v1.35.2) for the K8s version check. '
                         'Omit to skip that check.')
    args = ap.parse_args()

    if not os.path.isdir(args.live_dump_dir):
        sys.exit(f'ERROR: live dump dir not found: {args.live_dump_dir}')
    if not os.path.isfile(args.config_env):
        sys.exit(f'ERROR: config.env not found: {args.config_env}')

    nodes = parse_inventory(args.config_env)
    pinned_kube = parse_kube_version(args.config_env)
    drift_count = 0

    # --- Kubernetes server version check -------------------------------------
    if args.kube_version:
        actual = args.kube_version.strip()
        if actual != pinned_kube:
            print(f'KUBE:   DRIFT  config.env={pinned_kube}  live={actual}')
            drift_count += 1
        else:
            print(f'KUBE:   clean  ({pinned_kube})')
    else:
        print('KUBE:   skipped (no --kube-version provided)')

    # --- Per-node machine config diff ----------------------------------------
    for name, ip, role in nodes:
        gen_path = os.path.join(args.generated_dir, role, f'{name}.yaml')
        live_path = os.path.join(args.live_dump_dir, f'{ip}.machineconfig-resource.yaml')

        if not os.path.exists(gen_path):
            print(f'{name:6s} DRIFT  missing generated config: {gen_path}')
            drift_count += 1
            continue
        if not os.path.exists(live_path):
            print(f'{name:6s} DRIFT  missing live dump: {live_path}')
            drift_count += 1
            continue

        gen_docs = load_generated(gen_path)
        try:
            live_docs = load_live(live_path)
        except ValueError as e:
            print(f'{name:6s} DRIFT  {e}')
            drift_count += 1
            continue

        # The v1alpha1 main doc: first generated doc; find it in live
        gen_v1 = gen_docs[0]
        live_v1 = next(
            (d for d in live_docs
             if isinstance(d, dict) and d.get('version') == 'v1alpha1' and 'machine' in d),
            None,
        )
        if live_v1 is None:
            print(f'{name:6s} DRIFT  no v1alpha1 doc in live machineconfig')
            drift_count += 1
            continue

        v1_diffs = list(deep_diff(live_v1, gen_v1))

        # Other kinds: keyed by (kind, name|hostname)
        def keyed(docs):
            out = {}
            for d in docs:
                if isinstance(d, dict) and d.get('kind'):
                    key = (d['kind'], d.get('name') or d.get('hostname'))
                    out[key] = d
            return out

        gen_other = keyed(gen_docs)
        live_other = keyed(live_docs)
        live_only = sorted(set(live_other) - set(gen_other))
        gen_only = sorted(set(gen_other) - set(live_other))
        shared_diff = [k for k in set(gen_other) & set(live_other)
                       if gen_other[k] != live_other[k]]

        node_drift = (len(v1_diffs) + len(live_only) + len(gen_only) + len(shared_diff))
        drift_count += node_drift

        if node_drift == 0:
            print(f'{name:6s} clean')
        else:
            print(f'{name:6s} DRIFT  v1alpha1={len(v1_diffs)}  '
                  f'live-only={live_only or "-"}  gen-only={gen_only or "-"}  '
                  f'shared-diff={shared_diff or "-"}')
            for path, kind in v1_diffs[:20]:
                print(f'        {kind:18s} {path}')

    print()
    if drift_count:
        print(f'FAIL: {drift_count} drift item(s) detected')
        sys.exit(1)
    print('PASS: no drift')


if __name__ == '__main__':
    main()
