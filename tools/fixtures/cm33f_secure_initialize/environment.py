"""Hash the actual WSL interpreter, loaded modules, QEMU and resolved DSOs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree
import execute

root,output=sys.argv[1:]
qemu=str(Path(root)/'usr/bin/qemu-system-arm')
ldd=subprocess.check_output(['ldd',qemu],text=True)
if 'not found' in ldd:
    raise SystemExit('Missing QEMU runtime library')
paths={str(Path(sys.executable).resolve()),str(Path(qemu).resolve()),__file__,
       str(Path(__file__).parents[1]/'cm33_secure_guards'/'aircr_rsp.py')}
for module in list(sys.modules.values()):
    name=getattr(module,'__file__',None)
    if name and Path(name).is_file(): paths.add(str(Path(name).resolve()))
for library in re.findall(r'(?:=>\s+)?(/[^\s]+)',ldd):
    if Path(library).is_file(): paths.add(str(Path(library).resolve()))
result={'Executable':sys.executable,'Python':sys.version,'Qemu':subprocess.check_output([qemu,'--version'],text=True),
        'Machines':subprocess.check_output([qemu,'-machine','help'],text=True),
        'Ldd':re.sub(r'0x[0-9a-f]+','ADDRESS',ldd),
        'Files':[{'Path':p,'SHA256':hashlib.sha256(Path(p).read_bytes()).hexdigest().upper()} for p in sorted(paths)]}
Path(output).write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'Files':len(paths),'Status':'PASS'}))
