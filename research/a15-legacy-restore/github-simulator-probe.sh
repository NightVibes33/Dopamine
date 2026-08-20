#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-research/a15-legacy-restore/data/simulator}"
mkdir -p "$OUT_DIR"

HOST_TXT="$OUT_DIR/host.txt"
RUNTIMES_JSON="$OUT_DIR/runtimes.json"
DEVICETYPES_JSON="$OUT_DIR/devicetypes.json"
DEVICES_JSON="$OUT_DIR/devices.json"
SIM_TXT="$OUT_DIR/simulator.txt"
REPORT_JSON="$OUT_DIR/simulator-capability.json"

{
  echo "== host =="
  sw_vers || true
  uname -a || true
  echo
  echo "== xcode =="
  xcodebuild -version || true
  echo
  echo "== simctl =="
  xcrun simctl help | head -n 8 || true
} > "$HOST_TXT"

xcrun simctl list runtimes -j > "$RUNTIMES_JSON"
xcrun simctl list devicetypes -j > "$DEVICETYPES_JSON"
xcrun simctl list devices -j > "$DEVICES_JSON"

readarray -t SELECTED < <(python3 - "$RUNTIMES_JSON" "$DEVICETYPES_JSON" <<'PY'
import json, re, sys
runtimes=json.load(open(sys.argv[1]))['runtimes']
devtypes=json.load(open(sys.argv[2]))['devicetypes']

def version_key(v):
    nums=re.findall(r'\d+', v or '')
    return tuple(int(x) for x in nums[:4])

ios=[r for r in runtimes if r.get('isAvailable', True) and r.get('identifier','').startswith('com.apple.CoreSimulator.SimRuntime.iOS-')]
if not ios:
    raise SystemExit('no available iOS Simulator runtime installed')
runtime=max(ios, key=lambda r: version_key(r.get('version') or r.get('name')))
preferred=[d for d in devtypes if d.get('name') == 'iPhone SE (3rd generation)']
if preferred:
    dev=preferred[0]
else:
    iphones=[d for d in devtypes if d.get('name','').startswith('iPhone')]
    if not iphones:
        raise SystemExit('no iPhone Simulator device type installed')
    dev=iphones[0]
print(runtime['identifier'])
print(runtime.get('name') or runtime.get('version') or runtime['identifier'])
print(dev['identifier'])
print(dev['name'])
PY
)

RUNTIME_ID="${SELECTED[0]}"
RUNTIME_NAME="${SELECTED[1]}"
DEVICE_TYPE_ID="${SELECTED[2]}"
DEVICE_TYPE_NAME="${SELECTED[3]}"

UDID="$(xcrun simctl create A15ResearchProbe "$DEVICE_TYPE_ID" "$RUNTIME_ID")"
cleanup() {
  xcrun simctl shutdown "$UDID" >/dev/null 2>&1 || true
  xcrun simctl delete "$UDID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

xcrun simctl boot "$UDID"
xcrun simctl bootstatus "$UDID" -b

{
  echo "runtime=$RUNTIME_NAME"
  echo "device_type=$DEVICE_TYPE_NAME"
  echo "udid=$UDID"
  echo "uname_m=$(xcrun simctl spawn "$UDID" uname -m 2>/dev/null || true)"
  echo "hw_machine=$(xcrun simctl spawn "$UDID" sysctl -n hw.machine 2>/dev/null || true)"
  echo "kernel_osversion=$(xcrun simctl spawn "$UDID" sysctl -n kern.osversion 2>/dev/null || true)"
  echo "kernel_ostype=$(xcrun simctl spawn "$UDID" sysctl -n kern.ostype 2>/dev/null || true)"
  echo "secure_or_usb_dev_nodes=$(xcrun simctl spawn "$UDID" sh -c 'ls /dev 2>/dev/null | grep -Ei "sep|secure|dfu|usb" | tr "\n" ","' 2>/dev/null || true)"
} > "$SIM_TXT"

python3 - "$RUNTIME_NAME" "$DEVICE_TYPE_NAME" "$SIM_TXT" "$REPORT_JSON" <<'PY'
import json, pathlib, sys
runtime, devtype, simtxt, out = sys.argv[1:]
kv={}
for line in pathlib.Path(simtxt).read_text(errors='replace').splitlines():
    if '=' in line:
        k,v=line.split('=',1); kv[k]=v
report={
  'analysis_kind':'github_hosted_xcode_iphone_simulator_capability_probe',
  'runtime':runtime,
  'device_type':devtype,
  'observed':{
    'uname_m':kv.get('uname_m'),
    'hw_machine':kv.get('hw_machine'),
    'kernel_osversion':kv.get('kernel_osversion'),
    'kernel_ostype':kv.get('kernel_ostype'),
    'secure_or_usb_named_dev_nodes':kv.get('secure_or_usb_dev_nodes'),
  },
  'research_scope':{
    'can_run_ios_userspace_simulator_code':True,
    'can_execute_target_t8110_securerom':False,
    'can_enter_physical_dfu_for_iphone14_6':False,
    'can_model_physical_sep_firmware':False,
    'can_validate_cand001_runtime_reachability':False,
    'can_validate_manifest_and_static_models':True,
    'can_run_safe_state_machine_harnesses':True,
  },
  'interpretation':[
    'Xcode Simulator is useful for app/userspace behavior and synthetic state-machine tests.',
    'It is not a hardware emulator for the retail iPhone14,6 boot ROM, physical USB DFU controller, or SEP.',
    'Therefore CAND-001 SecureROM runtime behavior cannot be validated by an iPhone Simulator alone.',
  ],
  'vulnerability_status':'NOT_ESTABLISHED',
}
pathlib.Path(out).write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
print(json.dumps(report, indent=2, sort_keys=True))
PY
