import sys, os
from ltchiptool.soc.ambz2.parse_partition import PT, BootImg, FWImg
fn, outdir = sys.argv[1], sys.argv[2]
f = open(fn, 'rb')
pt = PT.parse_stream(f)
p = pt.data
print('boot rec', hex(p.boot_record.start_address), hex(p.boot_record.length))
for i, r in enumerate(p.part_records):
    print(f'part {i+1}: {r.type} @0x{r.start_address:X} len 0x{r.length:X}')
def dump_sections(tag, img_off):
    f.seek(img_off)
    fw = FWImg.parse_stream(f)
    print(f'{tag}: ota_sig {"empty" if fw.ota_signature==b"\xff"*32 else "set"}')
    for si, sub in enumerate(fw.sub_imgs):
        print(f'  sub{si} type={sub.hdr.type} enc={sub.hdr.is_encrypted} size=0x{sub.hdr.segment_size:X}')
        if sub.data is None: continue
        print(f'    fst flags={sub.data.fst.flags} ')
        for k, s in enumerate(sub.data.sections):
            e = s.entry_hdr
            name = f'{tag}_sub{si}_sec{k}_{s.type}_0x{e.section_base:08X}.bin'
            open(os.path.join(outdir, name), 'wb').write(s.image[:e.len] if e.len <= len(s.image) else s.image)
            print(f'    sec{k} {s.type} base=0x{e.section_base:08X} len=0x{e.len:X} entry=0x{e.entry_address:08X} sce={s.sce_enable} -> {name}')
f.seek(p.boot_record.start_address)
b = BootImg.parse_stream(f)
e = b.entry_hdr
open(os.path.join(outdir, f'boot_0x{e.section_base:08X}.bin'),'wb').write(b.image[:e.len])
print(f'boot: enc={b.hdr.is_encrypted} base=0x{e.section_base:08X} len=0x{e.len:X} entry=0x{e.entry_address:08X}')
for i, r in enumerate(p.part_records):
    if str(r.type) in ('FW1','FW2'):
        try: dump_sections(str(r.type), r.start_address)
        except Exception as ex: print(r.type, 'parse error', ex)
