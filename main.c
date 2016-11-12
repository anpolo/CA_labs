#include "stdlib.h"
#include "stdio.h"
#include "string.h"


#define CR0_PE 0
#define CR0_PG 31
#define CR4_PSE 4
#define MASK(x) (1<<(x))
#define PF_EXCEPTION 14

typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;

#pragma pack (push, 1)
typedef struct _DTR {
    uint16 limit;
    uint32 base;
    uint16 _padding;
} DTR, *PDTR;

typedef union _DESCRIPTOR {
    struct {
        uint32 low;
        uint32 high;
    } raw;
    struct {
        //3A.figure 3-8
        uint16 limit_low;
        uint16 base_low;
        uint8  base_mid;
        uint8  type:4;
        uint8  s:1;
        uint8  dpl:2;
        uint8  p:1;
        uint8 limit_high:4;
        uint8 avl:1;
        uint8 rsrvd:1;      //L bit only in 64bit
        uint8 db:1;
        uint8 g:1;
        uint8 base_high;
    } desc;
    struct {
        uint16 offset_low;
        uint16 segmSelector;
        uint8  reserv1:5;
        uint8  reserv2:3;
        uint8  type:5;
        uint8  dpl:2;
        uint8  p:1;
        uint16 offset_hight;
    } int_gate;
} DESCRIPTOR, *PDESCRIPTOR;

typedef union _PTE {
    uint32 raw;
    struct {
        uint32 p:1;
        uint32 rw:1;
        uint32 us:1;
        uint32 xx:4; //PCD,PWT,A,D
        uint32 ps:1;
        uint32 g:1;
        uint32 avl:3;
        uint32 pfn:20;
    };
} PTE, *PPTE;
#pragma pack (pop)

#define PTE_TRIVIAL_SELFMAP     0x007  //               //present read-write user 4Kb
#define PTE_TRIVIAL_LARGE       0x087  //0000 1000 0111 //present read-write user 4Mb
#define PTE_TRIVIAL_NONPRESENT  0xBA4  //---- ---- ---0
#define PTE_TRIVIAL_FAULTONCE   0x086  //same as PTE_TRIVIAL_LARGE but non-present

#define BASE_FROM_DESCRIPTOR(x) ((x->desc.base_low) | (x->desc.base_mid << 16) | (x->desc.base_high << 24))
#define LIMIT_FROM_DESCRIPTOR(x) (((x->desc.limit_low) | (x->desc.limit_high << 16)) << (x->desc.g ? 12 : 0))

typedef struct _SYSINFO {
    uint32 cpl;
    uint32 cr0;
    DTR gdt;
    DTR idt;
    DTR ldt;
    DTR tss;
    uint16 ldtr;
    uint16 tr;
} SYSINFO, *PSYSINFO;

typedef struct _IDTENTRY {
    uint16 offset_l;
    uint16 seg_sel;
    uint8  zero;
    uint8  flags;
    uint16 offset_h;
} IDTENTRY, *PIDTENTRY;

void idt_set_gate(PIDTENTRY idt, uint8 num, uint32 offset, uint16 seg_sel, uint8 flags) {
    idt[num].offset_l = offset & 0xFFFF;
    idt[num].offset_h = (offset >> 16) & 0xFFFF;
    idt[num].seg_sel = seg_sel;
    idt[num].zero = 0;
    idt[num].flags = flags;
}

//TODO setup proper page addr & its pte addr
uint32 PF_ADDR = 0;
uint32 my_ptr = 0;
uint32 incr = 0;

void __declspec( naked ) pf_handler(void) 
{
    __asm {
        //cli
        push eax
        push edx
        mov edx, cr2
        cmp edx, PF_ADDR        //"my" address
        jnz pf
        mov eax, my_ptr         //pde/pte corresponding to "my" unpresent address
        or dword ptr[eax], 1h   //restore P bit
        invlpg [eax]            //invalidate all paging caches for "my" address
        lea eax, incr           
        add [eax], 1            //inc counter of "my" #PF
        jmp done
pf:
        pop edx
        pop eax
        push old_segment
        push old_offset
        retf 
done:
        pop edx
        pop eax
        //sti
        add esp, 4
        iretd
    }
}

void get_sysinfo(PSYSINFO sysinfo)
{
    uint32 _cpl  = 0;
    uint32 _cr0  = 0;

    DTR* _gdt = &sysinfo->gdt;
    DTR* _idt = &sysinfo->idt;
    DTR* _ldt = &sysinfo->ldt;
    DTR* _tss = &sysinfo->tss;

    __asm {
        //read cpl as code selector RPL (see 3A.X.Y)
        mov ax,cs
        and eax, 3
        mov _cpl, eax
        //store cr0 (see 3A.2.5 for bits)
        mov eax, cr0
        mov _cr0, eax
        //store gdt/idt (see 3A.X.Y)
        mov eax, _gdt
        sgdt [eax]
        mov eax, _idt
        sidt [eax]
        // ldt
        mov eax, _ldt
        sldt [eax]
        //
        mov eax, _tss
        str [eax]
    }

    sysinfo->cpl = _cpl;
    sysinfo->cr0 = _cr0;
}

const char* get_str_type_by_code(uint8 type)
{
    switch(type)
    {
        case 0:  return "Data Read-Only";
        case 1:  return "Data Read-Only, accessed";
        case 2:  return "Data Read/Write";
        case 3:  return "Data Read/Write, accessed";
        case 4:  return "Data Read-Only, expand-down";
        case 5:  return "Data Read-Only, expand-down, accessed";
        case 6:  return "Data Read/Write, expand-down";
        case 7:  return "Data Read/Write, expand-down, accessed";

        case 8:  return "Code Execute-Only";
        case 9:  return "Execute-Only, accessed";
        case 10: return "Execute/Read";
        case 11: return "Execute/Read, accessed";
        case 12: return "Execute-Only, conforming";
        case 13: return "Execute-Only, conforming, accessed";
        case 14: return "Execute/Read, conforming";
        case 15: return "Execute/Read, conforming, accessed";
        
        default: return "Not matching";
    }
}

const char* get_str_stype_by_code(uint8 type)
{
    switch(type)
    {
        case 0:  return "Reserved";
        case 1:  return "16-bit TSS(Available)";
        case 2:  return "LDT";
        case 3:  return "16-bit TSS(Busy)";
        case 4:  return "16-bit Call Gate";
        case 5:  return "Task Gate";
        case 6:  return "16-bit Interrupt Gate";
        case 7:  return "16-bit Trap Gate";

        case 8:  return "Reserved";
        case 9:  return "32-bit TSS(Available)";
        case 10: return "Reserved";
        case 11: return "32-bit TSS(Busy)";
        case 12: return "32-bit Call Gate";
        case 13: return "Reserved";
        case 14: return "32-bit Interrupt Gate";
        case 15: return "32-bit Trap Gate";
        
        default: return "Not matching";
    }
}

const char* get_str_type_idt(uint8 type)
{
    switch(type & 0x7)
    {
        case 5: return "Task Gate";
        case 6: return "Interrupt Gate";
        case 7: return "Trap Gate";

        default: return "Not matching";
    }
}

void fprint_descripor(FILE* f, PDESCRIPTOR d)
{
    fprintf(f, "\tVALUE=0x%08X-%08X PRESENT=%s \n", d->raw.high, d->raw.low, d->desc.p ? "yes":"no");

    if (d->desc.p && !d->desc.s) {
        fprintf(f, "\tBASE=0x%08X LIMIT=0x%08X \n", BASE_FROM_DESCRIPTOR(d), LIMIT_FROM_DESCRIPTOR(d));
        fprintf(f, "\tRING=%d TYPE=%s SYSTEM=%s DB=%s\n", 
            d->desc.dpl, get_str_stype_by_code(d->desc.type), d->desc.s ? "segment":"system", d->desc.db ? "32bit":"16bit");
    }
    else if (d->desc.p) {
        fprintf(f, "\tBASE=0x%08X LIMIT=0x%08X \n", BASE_FROM_DESCRIPTOR(d), LIMIT_FROM_DESCRIPTOR(d));
        fprintf(f, "\tRING=%d TYPE=%s SYSTEM=%s DB=%s\n", 
            d->desc.dpl, get_str_type_by_code(d->desc.type), d->desc.s ? "segment":"system", d->desc.db ? "32bit":"16bit");
    }
}

#define OFFSET_FROM_INTERRUPT(x) ((x->int_gate.offset_low) | (x->int_gate.offset_hight << 16))

void fprint_idt_table(FILE* f, PDESCRIPTOR d)
{
    fprintf(f, "\tVALUE=0x%08X-%08X PRESENT=%s\n", d->raw.high, d->raw.low, d->desc.p ? "yes":"no");

    if(d->int_gate.p){
        fprintf(f, "\tOFFSET=0x%08X  DPL=0x%X TYPE=0x%s RESERV=0x%X SEGM_SEL=0x%X\n", 
            OFFSET_FROM_INTERRUPT(d), d->int_gate.dpl, get_str_type_idt(d->int_gate.type), d->int_gate.reserv1, d->int_gate.segmSelector);
    }
}

enum TABLE_TYPE{TABLE_ANY=0, TABLE_IDT};

void fprint_desctable(FILE* f, uint32* base, uint32 limit, uint8 type)
{
    DESCRIPTOR d;

    int i;
    for(i=0;;i++) { //i is an index in the array of 64bit descriptors
        fprintf(f, "element %d (selector = %04X): \n", i, i<<3);
        if (i*8 > limit) break;

        d.raw.low = base[i*2];
        d.raw.high = base[i*2+1];

        if (type == TABLE_ANY){
            fprint_descripor(f, &d);
        } else {
            fprint_idt_table(f, &d);
        }
    }
}

void fprint_tables(PSYSINFO sysinfo)
{
    FILE* gdt_dump;
    FILE* idt_dump;
    FILE* ldt_dump;
    FILE* tss_dump;
        
    //print GDT
    gdt_dump = fopen("A:\\gdt_dump.txt","w");
    if (0 == gdt_dump) {
        printf("ERROR: cannot fopen gdt_dump \n");
    } else {
        fprint_desctable(gdt_dump, (uint32*)sysinfo->gdt.base, sysinfo->gdt.limit, TABLE_ANY);
    }

    //print IDT
    idt_dump = fopen("A:\\idt_dump.txt","w");
    if (0 == idt_dump) {
        printf("ERROR: cannot fopen gdt_dump \n");
    } else {
        fprint_desctable(idt_dump, (uint32*)sysinfo->idt.base, sysinfo->idt.limit, TABLE_IDT);
    }

    //print LDT
    ldt_dump = fopen("A:\\ldt_dump.txt","w");
    if(0 == ldt_dump) {
        printf("ERROR: cannot fopen ldt_dump");
    } else {
        fprint_desctable(ldt_dump, (uint32*)sysinfo->ldt.base, sysinfo->ldt.limit, TABLE_ANY);    
    }

    //print TSS
    tss_dump = fopen("A:\\tss_dump.txt","w");
    if(0 == tss_dump) {
        printf("ERROR: cannot fopen ldt_dump");
    } else {
        fprint_desctable(tss_dump, (uint32*)sysinfo->tss.base, sysinfo->tss.limit, TABLE_ANY);    
    }

    fclose(gdt_dump);
    fclose(idt_dump);
    fclose(ldt_dump);
    fclose(tss_dump);
}

void paging_task()
{
    int i;
    char* addr = (char*)0x1FC00000;
    void* p = malloc(8*1024*1024);
    uint32 _p = (uint32)p;
    uint32 _p_aligned = (_p & 0xFFC00000) + 4*1024*1024;
    uint32 _pd = _p_aligned + 0;
    PPTE pd = (PPTE)_pd;
    printf("malloc 8Mb at 0x%08X-0x%08x, aligned at 0x%08X \n", _p, _p+8*1024*1024, _p_aligned);
    //trivial mapping
    for (i=0;i<1024;i++) {
        pd[i].raw = i*0x400000;
        pd[i].raw |= (i<512) ? PTE_TRIVIAL_LARGE : PTE_TRIVIAL_NONPRESENT;
    }
    //self-mapping
    pd[0x3c0].raw = _p_aligned | PTE_TRIVIAL_SELFMAP; //self-mapped to 0xF0000000
    //unmap 0x1FC00000 address, this addr should be less than phys mem available to VM!!!
    pd[0x7F].raw &= 0xFFFFFFFE; //virtual range 0x1FC00000-0x1FFFFFFF is unpresent
    __asm {
        pushfd
        cli
        mov eax, _p_aligned
        mov cr3, eax         //this also resets instruction cache
        mov eax, cr4
        or eax, 0x90
        mov cr4, eax        //enable CR4.PSE and CR4.PGE
        mov eax, cr0
        or eax, 0x80000000
        mov cr0, eax        //enable CR0.PG
        popfd
    }
    //printf("Read from 0x%08X = %x", addr, *addr);
}

void pf_test(PSYSINFO sysinfo)
{
    PIDTENTRY idt_table = (PIDTENTRY)sysinfo->idt.base;
    uint32 old_offset = idt_table[PF_EXCEPTION].offset_h << 16 | idt_table[PF_EXCEPTION].offset_l;
    uint16 old_segment = idt_table[PF_EXCEPTION].seg_sel;
    uint32 new_offset = 0;
    uint16 new_segment = 0;
    uint32 *addr = NULL;
    
    printf("MY PF counter: %d\n", incr);
    __asm {
        mov edx, offset pf_handler
        mov new_offset, edx
        mov ax, seg pf_handler
        mov new_segment, ax
    }

    //printf("old: offset 0x%p segment 0x%p \n", old_offset, old_segment);
    //printf("func: 0x%p \n", pf_handler);
    //printf("offset: 0x%x segment: 0x%x \n", new_offset, new_segment);
    
    idt_set_gate(idt_table, PF_EXCEPTION, (uint32)new_offset, new_segment, idt_table[PF_EXCEPTION].flags);
    
    addr = (uint32 *)PF_ADDR;
    printf("I am memory %d\n", *addr); // to recover page
    //printf("I am memory %d\n", *(addr + 4)); // to see default page fault
 
    printf("MY PF: %d\n", incr);

}


int main(int argc, const char* argv[])
{
    SYSINFO sysinfo;

    if( argc <= 1)
    {
        printf("ERROR: no arguments!\n");
        return 1;
    }

    memset(&sysinfo, 0, sizeof(sysinfo));
    get_sysinfo(&sysinfo);
    
    printf("Protected Mode: %s \n", (sysinfo.cr0 & MASK(CR0_PE))?"on":"off");
    printf("Paging Mode: %s \n",    (sysinfo.cr0 & MASK(CR0_PG))?"on":"off");
    printf("Ring: CPL=%d \n",       sysinfo.cpl);
    printf("================ \n");
    printf("GDT: base=0x%08X limit=0x%04X \n", sysinfo.gdt.base, sysinfo.gdt.limit);
    printf("IDT: base=0x%08X limit=0x%04X \n", sysinfo.idt.base, sysinfo.idt.limit);
    printf("LDT: base=0x%08X limit=0x%04X \n", sysinfo.ldt.base, sysinfo.ldt.limit);
    printf("TSS: base=0x%08X limit=0x%04X \n", sysinfo.tss.base, sysinfo.tss.limit);

    if(strcmp(argv[1], "table") == 0)
        fprint_tables(&sysinfo);
    else if(strcmp(argv[1], "table") == 0)
        paging_task();
    else
    {
        printf("ERROR: argument no matching!\n");
        return 1;
    }

    __asm {
        xor ax,ax
        mov cs,ax
    }

    return 0;
}
