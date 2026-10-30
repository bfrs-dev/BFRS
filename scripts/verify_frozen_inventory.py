"""Run the production windowed EXE in isolation; never import repository code."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def verify(executable, workspace):
    workspace = Path(workspace)
    workspace.mkdir(parents=True,exist_ok=True)
    destination = workspace/'smoke'
    environment = dict(os.environ)
    for key in ('PYTHONPATH','PYTHONHOME'):
        environment.pop(key,None)
    environment['QT_QPA_PLATFORM']='offscreen'
    result = subprocess.run([str(Path(executable).resolve()),'--inventory-smoke-test',str(destination)],
                            cwd=workspace,env=environment,timeout=120)
    outcome = json.loads((destination/'smoke-result.json').read_text(encoding='utf-8'))
    required = ('ok', 'frozen', 'no_console', 'cli_gui_equal', 'resume',
                'raw_zip_scan', 'raw_zip_resume', 'raw_zip_cli_gui_equal')
    if result.returncode or outcome.get('tabs') != 4 or not all(outcome.get(key) is True for key in required):
        raise RuntimeError('Frozen inventory check failed:\n' + json.dumps(outcome,ensure_ascii=True,indent=2))
    print(json.dumps(outcome,ensure_ascii=True,indent=2))
    return outcome


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe',type=Path,required=True)
    parser.add_argument('--work',type=Path)
    arguments=parser.parse_args()
    if arguments.work:
        verify(arguments.exe,arguments.work)
    else:
        with tempfile.TemporaryDirectory(prefix='bfrs-frozen-inventory-') as directory:
            verify(arguments.exe,directory)


if __name__=='__main__':
    main()
