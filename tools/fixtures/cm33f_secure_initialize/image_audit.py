"""Decode production text bytes; export immutable real-image RSP facts."""
import hashlib
import json
import re
import sys
from pathlib import Path
from elftools.elf.elffile import ELFFile


def require(test, message):
    if not test:
        raise RuntimeError(message)


def read(path,control='none'):
    with open(path, 'rb') as stream:
        elf = ELFFile(stream)
        symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
        sections = [{k: s[k] for k in ('sh_addr','sh_size','sh_flags')} | {'data':s.data()}
                    for s in elf.iter_sections()]
        facts = {s.name:{'address':s['st_value'] & ~1,'size':s['st_size']} for s in symbols}
        funcs = sorted(set(s['st_value'] & ~1 for s in symbols if s['st_info']['type']=='STT_FUNC'))
        decoded = {}
        for line in Path(path+'.dis').read_text().splitlines():
            m = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4,8}\s+)+)([a-z][a-z0-9.]*)\s*(.*)',line)
            if m:
                pc = int(m[1],16)
                decoded[pc] = {'pc':pc,'size':sum(len(x)//2 for x in m[2].split()),
                               'op':m[3],'args':m[4].split('@')[0].strip(),'text':line}
        production, bodies, code_hash, instruction_bytes, literal_bytes = {}, {}, hashlib.sha256(), 0, 0
        prefixes = ('__acle_se_fiber_secure_', 'fiber_secure_context_pool_',
                    'fiber_secure_context_gateway_fail_closed')
        for s in symbols:
            if s['st_info']['type']!='STT_FUNC' or not s.name.startswith(prefixes):
                continue
            start = s['st_value'] & ~1
            section = sections[s['st_shndx']]
            end = min([x for x in funcs if x>start]+[section['sh_addr']+section['sh_size']])
            end = min(end,section['sh_addr']+section['sh_size'])
            marks = sorted(set((x['st_value'],x.name[:2]) for x in symbols if
                           x['st_shndx']==s['st_shndx'] and x.name[:2] in ('$t','$d')))
            require(any(a==start and tag=='$t' for a,tag in marks),'MAPPING_START:'+s.name)
            bounds = [x for x in marks if start<=x[0]<end]+[(end,'$end')]
            own = []
            for (a,kind),(b,_) in zip(bounds,bounds[1:]):
                if kind=='$d':
                    literal_bytes += b-a
                    continue
                require(kind=='$t','MAPPING_KIND')
                while a<b:
                    require(a in decoded,'DECODE_COVERAGE')
                    item=decoded[a]
                    require(a+item['size']<=b,'DECODE_EXTENT')
                    require(not item['op'].startswith('v'),'FP_ENVELOPE')
                    if item['op']=='msr' and item['args'].lower().startswith('cpsr_fs'):
                        require(re.search(r'f38e\s+8c00\s+msr\s+CPSR_fs, lr',item['text']), 'APSR_ENCODING')
                    require(item['op'] not in ('blxns',),'UNEXPECTED_NS_UPCALL')
                    raw=section['data'][a-section['sh_addr']:a-section['sh_addr']+item['size']]
                    code_hash.update(raw)
                    instruction_bytes += item['size']
                    production[a]=item
                    own.append(item)
                    a += item['size']
            raw=section['data'][start-section['sh_addr']:end-section['sh_addr']]
            bodies[s.name]={'start':start,'end':end,'sha256':hashlib.sha256(raw).hexdigest().upper(),
                            'instructions':own,'udf':[x['pc'] for x in own if x['op']=='udf']}
        entries={}
        for name,body in bodies.items():
            if not name.startswith('__acle_se_'):
                continue
            public=name[len('__acle_se_'):]
            require(public in facts and facts[public]['size']==8,'VENEER_SYMBOL')
            address=facts[public]['address']
            a,b=decoded.get(address),decoded.get(address+4)
            require(a and b and a['op']=='sg' and a['size']==4 and b['size']==4 and
                    b['op'] in ('b','b.w') and int(b['args'].split()[0],16)==body['start'], 'VENEER_EXTENT')
            entries[public]={'body':body['start'],'veneer':address,'udf':body['udf'],
                             'returns':[x['pc'] for x in body['instructions'] if x['op']=='bxns']}
            # The integer CPACR/nPRIV guard and trap must exist in every body.
            text='\n'.join(x['text'] for x in body['instructions'])
            preflight='CONTROL' in text and '#75' in text and text.count('#15728640')>=2
            if control=='query-preflight' and public=='fiber_secure_gateway_c3fs_v1_abi_version':
                require(not preflight,'CONTROL_PREFLIGHT_NOT_REMOVED')
            else:
                require(preflight,'PREFLIGHT')
        if production:
            require(len(entries)==9,'EXACT_NINE_ENTRIES')
            pool=bodies['fiber_secure_context_pool_boot_initialize']['instructions']
            reads=[x for x in pool if x['op'].startswith('ldrb')]
            require(len(reads)==1,'POOL_READ_LOOP')
            read_pc=reads[0]['pc']
            backs=[x for x in pool if x['pc']>read_pc and x['op'].startswith('b') and
                   re.match(r'^[0-9a-f]+\s',x['args']) and int(x['args'].split()[0],16)<=read_pc]
            require(backs,'POOL_READ_BACKEDGE')
            back=backs[0]
            read_done=back['pc']+back['size']
        else:
            read_pc=read_done=0
        return {'symbols':facts,'entries':entries,'bodies':bodies,
                'instructions':list(production.values()),'pool_read':read_pc,'pool_read_done':read_done,
                'instruction_bytes':instruction_bytes,'literal_bytes':literal_bytes,
                'instruction_sha256':code_hash.hexdigest().upper()}


def main():
    secure,ns,output=sys.argv[1:4]
    control=sys.argv[4] if len(sys.argv)>4 else 'none'
    require(control in ('none','query-preflight','ns-fpca','pool-exact','control-exact','GRO','fp-nop'),'CONTROL_KIND')
    s,n=read(secure,control),read(ns)
    manifest={'secure':s,'nonsecure':n,'secure_sha256':hashlib.sha256(Path(secure).read_bytes()).hexdigest().upper(),
              'nonsecure_sha256':hashlib.sha256(Path(ns).read_bytes()).hexdigest().upper(),'control':control}
    Path(output).write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'ProductionInstructions':len(s['instructions']),'BodyCount':len(s['bodies']),
                      'InstructionBytes':s['instruction_bytes'],'LiteralBytes':s['literal_bytes'],
                      'InstructionSHA256':s['instruction_sha256'],'Status':'PASS'}))


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print('REJECT:'+str(error))
        sys.exit(1)
