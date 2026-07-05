#!/usr/bin/env python3
"""Attribute bytes in EVM runtime bytecode: opcode histogram, duplicate basic
blocks (exact and label-normalized), and boilerplate pattern counts."""
import sys
from collections import Counter, defaultdict

NAMES = {0x00:'STOP',0x01:'ADD',0x02:'MUL',0x03:'SUB',0x04:'DIV',0x05:'SDIV',0x06:'MOD',
0x07:'SMOD',0x08:'ADDMOD',0x09:'MULMOD',0x0a:'EXP',0x0b:'SIGNEXTEND',0x10:'LT',0x11:'GT',
0x12:'SLT',0x13:'SGT',0x14:'EQ',0x15:'ISZERO',0x16:'AND',0x17:'OR',0x18:'XOR',0x19:'NOT',
0x1a:'BYTE',0x1b:'SHL',0x1c:'SHR',0x1d:'SAR',0x20:'KECCAK',0x30:'ADDRESS',0x31:'BALANCE',
0x32:'ORIGIN',0x33:'CALLER',0x34:'CALLVALUE',0x35:'CALLDATALOAD',0x36:'CALLDATASIZE',
0x37:'CALLDATACOPY',0x38:'CODESIZE',0x39:'CODECOPY',0x3a:'GASPRICE',0x3b:'EXTCODESIZE',
0x3d:'RETURNDATASIZE',0x3e:'RETURNDATACOPY',0x3f:'EXTCODEHASH',0x40:'BLOCKHASH',0x41:'COINBASE',
0x42:'TIMESTAMP',0x43:'NUMBER',0x44:'PREVRANDAO',0x45:'GASLIMIT',0x46:'CHAINID',0x47:'SELFBALANCE',
0x48:'BASEFEE',0x50:'POP',0x51:'MLOAD',0x52:'MSTORE',0x53:'MSTORE8',0x54:'SLOAD',0x55:'SSTORE',
0x56:'JUMP',0x57:'JUMPI',0x58:'PC',0x59:'MSIZE',0x5a:'GAS',0x5b:'JUMPDEST',0x5e:'MCOPY',
0x5f:'PUSH0',0xf0:'CREATE',0xf1:'CALL',0xf2:'CALLCODE',0xf3:'RETURN',0xf4:'DELEGATECALL',
0xf5:'CREATE2',0xfa:'STATICCALL',0xfd:'REVERT',0xfe:'INVALID',0xff:'SELFDESTRUCT'}
for i in range(32): NAMES[0x60+i]=f'PUSH{i+1}'
for i in range(16): NAMES[0x80+i]=f'DUP{i+1}'; NAMES[0x90+i]=f'SWAP{i+1}'
for i in range(5): NAMES[0xa0+i]=f'LOG{i}'
TERM = {0x00,0x56,0xf3,0xfd,0xfe,0xff}  # STOP JUMP RETURN REVERT INVALID SELFDESTRUCT

def disasm(code):
    out=[]; i=0
    while i < len(code):
        op=code[i]
        if 0x60<=op<=0x7f:
            n=op-0x5f; out.append((i,op,code[i+1:i+1+n])); i+=1+n
        else: out.append((i,op,b'')); i+=1
    return out

def main(path, label):
    code=bytes.fromhex(open(path).read().strip())
    ins=disasm(code)
    print(f'== {label}: {len(code)} bytes, {len(ins)} instructions ==')
    # opcode byte attribution
    byt=Counter()
    for _,op,imm in ins: byt[NAMES.get(op,hex(op))]+=1+len(imm)
    top=byt.most_common(14)
    print('top opcodes by bytes:', ', '.join(f'{k}={v}' for k,v in top))
    push_bytes=sum(v for k,v in byt.items() if k.startswith('PUSH'))
    dupswap=sum(v for k,v in byt.items() if k.startswith(('DUP','SWAP')))
    mem=sum(byt[k] for k in ('MLOAD','MSTORE','MSTORE8') if k in byt)
    print(f'  PUSH*={push_bytes} ({100*push_bytes/len(code):.0f}%)  DUP/SWAP={dupswap} ({100*dupswap/len(code):.0f}%)  MLOAD/MSTORE={mem}')
    # basic blocks
    blocks=[]; cur=[]
    for t in ins:
        if t[1]==0x5b and cur: blocks.append(cur); cur=[]
        cur.append(t)
        if t[1] in TERM or t[1]==0x57: blocks.append(cur); cur=[]
    if cur: blocks.append(cur)
    def size(b): return sum(1+len(imm) for _,_,imm in b)
    # exact duplicates (identical bytes incl. immediates)
    exact=defaultdict(list)
    for b in blocks:
        key=tuple((op,bytes(imm)) for _,op,imm in b)
        exact[key].append(b)
    save_exact=sum((len(v)-1)*size(v[0]) for v in exact.values() if len(v)>1)
    ndup=sum(len(v)-1 for v in exact.values() if len(v)>1)
    print(f'  blocks={len(blocks)}; exact-duplicate blocks={ndup}, bytes recoverable by exact dedup={save_exact}')
    biggest=sorted((x for x in exact.values() if len(x)>1), key=lambda v:(len(v)-1)*size(v[0]), reverse=True)[:5]
    for v in biggest:
        b=v[0]; ops=' '.join(NAMES.get(op,hex(op)) for _,op,_ in b[:10])
        print(f'    {len(v)}x {size(b)}B: {ops}{"..." if len(b)>10 else ""}')
    # label-normalized duplicates (PUSH2/PUSH3 imm wildcarded) - upper bound
    norm=defaultdict(list)
    for b in blocks:
        key=tuple((op, b'' if op in (0x61,0x62) else bytes(imm)) for _,op,imm in b)
        norm[key].append(b)
    save_norm=sum((len(v)-1)*size(v[0]) for v in norm.values() if len(v)>1)
    print(f'  label-normalized dedup upper bound: {save_norm} bytes')
    # patterns
    hexs=code.hex()
    print(f'  panic selector (4e487b71) sites={hexs.count("4e487b71")}, Error(string) (08c379a0) sites={hexs.count("08c379a0")}')
    # internal call shape: PUSH2 ret; PUSH2 fn; JUMP  /  and JUMPDESTs
    seq=0
    for a,b2 in zip(ins,ins[1:]):
        if NAMES.get(a[1],'').startswith('PUSH2') and b2[1]==0x56: seq+=1
    print(f'  PUSH2+JUMP pairs (calls/jumps)={seq}, JUMPDESTs={byt.get("JUMPDEST",0)}')
    print()

if __name__=='__main__':
    main(sys.argv[1], sys.argv[2])
