/*
 * Copyright (c) 2006-2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author      Notes
 * 2018/08/29     Bernard     first version
 * 2021/04/23     chunyexixiaoyu    distinguish 32-bit and 64-bit
 */

#include "dlmodule.h"
#include "dlelf.h"

#define DBG_TAG    "DLMD"
#define DBG_LVL    DBG_INFO
#include <rtdbg.h>          // must after of DEBUG_ENABLE or some other options

rt_err_t dlmodule_load_shared_object(struct rt_dlmodule* module, void *module_ptr)
{
    rt_bool_t linked   = RT_FALSE;
    rt_ubase_t  index, module_size = 0;
    Elf_Addr vstart_addr, vend_addr;
    rt_bool_t has_vstart;

    RT_ASSERT(module_ptr != RT_NULL);

    /* 判断当前的ELF文件，是否被链接过，此标志在重定位过程中将被使用到 */
    if (rt_memcmp(elf_module->e_ident, RTMMAG, SELFMAG) == 0)
    {
        /* rtmlinker finished */
        linked = RT_TRUE;
    }

    
    /* 通过对ELF文件的program header解析，计算可加载段的起始和结束地址，以及文件长度，为后续将该内存拷贝到mem_space中做准备*/
    has_vstart = RT_FALSE;
    vstart_addr = vend_addr = RT_NULL;
    for (index = 0; index < elf_module->e_phnum; index++)
    {
        // 当前未不可加载段的话，则不关心
        if (phdr[index].p_type != PT_LOAD)
            continue;

        LOG_D("LOAD segment: %d, 0x%p, 0x%08x", index, phdr[index].p_vaddr, phdr[index].p_memsz);

        if (phdr[index].p_memsz < phdr[index].p_filesz)
        {
            rt_kprintf("invalid elf: segment %d: p_memsz: %d, p_filesz: %d\n",
                       index, phdr[index].p_memsz, phdr[index].p_filesz);
            return RT_NULL;
        }

        // 记录第一个可加载段的起始地址（p_vaddr)
        if (!has_vstart)
        {
            vstart_addr = phdr[index].p_vaddr;
            vend_addr = phdr[index].p_vaddr + phdr[index].p_memsz;
            has_vstart = RT_TRUE;
            if (vend_addr < vstart_addr)
            {
                LOG_E("invalid elf: segment %d: p_vaddr: %d, p_memsz: %d\n",
                           index, phdr[index].p_vaddr, phdr[index].p_memsz);
                return RT_NULL;
            }
        }
        else
        {
            // 判断ELF文件的有效性
            if (phdr[index].p_vaddr < vend_addr)
            {
                LOG_E("invalid elf: segment should be sorted and not overlapped\n");
                return RT_NULL;
            }
            if (phdr[index].p_vaddr > vend_addr + 16)
            {
                /* There should not be too much padding in the object files. */
                LOG_W("warning: too much padding before segment %d", index);
            }

            // 记录最后一个可加载段中的结束地址（p_vaddr + p_memsz）
            vend_addr = phdr[index].p_vaddr + phdr[index].p_memsz;
            if (vend_addr < phdr[index].p_vaddr)
            {
                LOG_E("invalid elf: "
                           "segment %d address overflow\n", index);
                return RT_NULL;
            }
        }
    }

    // 需要拷贝到mem_space中长度
    module_size = vend_addr - vstart_addr;
    LOG_D("module size: %d, vstart_addr: 0x%p", module_size, vstart_addr);
    if (module_size == 0)
    {
        LOG_E("Module: size error\n");
        return -RT_ERROR;
    }

    // ELF文件中，第一个可加载段的起始地址（p_vaddr)
    module->vstart_addr = vstart_addr;
    module->nref = 0;

    /* allocate module space */
    module->mem_space = rt_malloc(module_size);
    if (module->mem_space == RT_NULL)
    {
        LOG_E("Module: allocate space failed.\n");
        return -RT_ERROR;
    }
    module->mem_size = module_size;

    /* zero all space */
    rt_memset(module->mem_space, 0, module_size);

    /* 将上面通过解析Program Header，得到的可加载段的内容，拷贝到mem_space中，待后续执行 */
    for (index = 0; index < elf_module->e_phnum; index++)
    {
        if (phdr[index].p_type == PT_LOAD)
        {
            rt_memcpy(module->mem_space + phdr[index].p_vaddr - vstart_addr,
                      (rt_uint8_t *)elf_module + phdr[index].p_offset,
                      phdr[index].p_filesz);
        }
    }

    /* 设置模块的执行地址 */
    module->entry_addr = module->mem_space + elf_module->e_entry - vstart_addr;

    /* 处理重定位的节section */
    for (index = 0; index < elf_module->e_shnum; index ++)
    {
        rt_ubase_t i, nr_reloc;
        Elf_Sym *symtab;
        Elf_Rel *rel;
        rt_uint8_t *strtab;
        static rt_bool_t unsolved = RT_FALSE;

        // 遍历所有的section, 只处理包含重定位信息的section，否则跳过处理
        #if (defined(__arm__) || defined(__i386__) || (__riscv_xlen == 32))
        if (!IS_REL(shdr[index]))
            continue;
        #elif (defined(__aarch64__) || defined(__x86_64__) || (__riscv_xlen == 64))
        if (!IS_RELA(shdr[index]))
            continue;
        #endif

        // 获取需要进行重定位的内容（item）
        rel = (Elf_Rel *)((rt_uint8_t *)module_ptr + shdr[index].sh_offset);

        /* locate .rel.plt and .rel.dyn section */
        // REL节的sh_link表示的是：该可重定位的节，使用到的符号表，在节头表中的下表
        // 这里symtab是符号表的实体数据
        symtab = (Elf_Sym *)((rt_uint8_t *)module_ptr +
                               shdr[shdr[index].sh_link].sh_offset);

        // symtab section中的st_link表示的是，该符号表，使用到的字符串表，在节头表中的下表
        // 符号表中使用到的字符串，所在的字符串节的实体数据
        strtab = (rt_uint8_t *)module_ptr +
                 shdr[shdr[shdr[index].sh_link].sh_link].sh_offset;

        // 可重定位的section，有多少个可重定位项目
        nr_reloc = (rt_ubase_t)(shdr[index].sh_size / sizeof(Elf_Rel));

        /* 可重定位项目，依次处理*/
        for (i = 0; i < nr_reloc; i ++)
        {
            #if (defined(__arm__) || defined(__i386__) || (__riscv_xlen == 32))
            // ELF32_R_SYM(rel->r_info) 这个表示该重定位信息，在符号表中的下标，根据下标，就可以找到具体的符号信息
            // sym: 需要重定位的符号信息（包括符号的名字（函数名），符号的值（函数地址））
            Elf_Sym *sym = &symtab[ELF32_R_SYM(rel->r_info)];
            #elif (defined(__aarch64__) || defined(__x86_64__) || (__riscv_xlen == 64))
            Elf_Sym *sym = &symtab[ELF64_R_SYM(rel->r_info)];
            #endif
            LOG_D("relocate symbol %s shndx %d", strtab + sym->st_name, sym->st_shndx);

            
            /* 符号，所在的节，如果是无效的，或者 符号类型是局部符号 */
            if ((sym->st_shndx != SHT_NULL) ||(ELF_ST_BIND(sym->st_info) == STB_LOCAL))
            {
                Elf_Addr addr;

                addr = (Elf_Addr)(module->mem_space + sym->st_value - vstart_addr);
                /*修改包含重定位内容的section中的重定位入口偏移地址处的值*/
                dlmodule_relocate(module, rel, addr);
            }
            // 如果是全局符号（外部函数），查找外部符号，然后接着重定位处理
            else if (!linked)
            {
                Elf_Addr addr;

                LOG_D("relocate symbol: %s", strtab + sym->st_name);
                /* need to resolve symbol in kernel symbol table */
                addr = dlmodule_symbol_find((const char *)(strtab + sym->st_name));
                if (addr == 0)
                {
                    LOG_E("Module: can't find %s in kernel symbol table", strtab + sym->st_name);
                    unsolved = RT_TRUE;
                }
                else
                {
                    dlmodule_relocate(module, rel, addr);
                }
            }
            rel ++;
        }

        if (unsolved)
            return -RT_ERROR;
    }

    /* 接下来构建模块的符号表 */

    /* 找到.dynsym section,在节头表中的index */
    for (index = 0; index < elf_module->e_shnum; index ++)
    {
        /* find .dynsym section */
        rt_uint8_t *shstrab;
        shstrab = (rt_uint8_t *)module_ptr +
                  shdr[elf_module->e_shstrndx].sh_offset;
        if (rt_strcmp((const char *)(shstrab + shdr[index].sh_name), ELF_DYNSYM) == 0)
            break;
    }

    /* found .dynsym section */
    if (index != elf_module->e_shnum)
    {
        int i, count = 0;
        Elf_Sym  *symtab = RT_NULL;
        rt_uint8_t *strtab = RT_NULL;

        // 动态符号表在ELF文件中的位置，由一个一个的Elf_Sym组成
        symtab = (Elf_Sym *)((rt_uint8_t *)module_ptr + shdr[index].sh_offset);

        // 动态符号表中，使用到的字符串表，在ELF文件中的位置
        strtab = (rt_uint8_t *)module_ptr + shdr[shdr[index].sh_link].sh_offset;

        // 动态符号表的item数
        for (i = 0; i < shdr[index].sh_size / sizeof(Elf_Sym); i++)
        {
            if ((ELF_ST_BIND(symtab[i].st_info) == STB_GLOBAL) &&
                (ELF_ST_TYPE(symtab[i].st_info) == STT_FUNC))
                count ++;
        }

        // 根据动态符号表，填充module->symtab表
        module->symtab = (struct rt_module_symtab *)rt_malloc
                         (count * sizeof(struct rt_module_symtab));
        module->nsym = count;
        for (i = 0, count = 0; i < shdr[index].sh_size / sizeof(Elf_Sym); i++)
        {
            rt_size_t length;

            if ((ELF_ST_BIND(symtab[i].st_info) != STB_GLOBAL) ||
                (ELF_ST_TYPE(symtab[i].st_info) != STT_FUNC))
                continue;

            // 符号在字符串表中的长度，包含最后一个0
            length = rt_strlen((const char *)(strtab + symtab[i].st_name)) + 1;


            // 填充模块symtab表，函数名和函数地址
            module->symtab[count].addr =
                (void *)(module->mem_space + symtab[i].st_value - module->vstart_addr);
            module->symtab[count].name = rt_malloc(length);
            rt_memset((void *)module->symtab[count].name, 0, length);
            rt_memcpy((void *)module->symtab[count].name,
                      strtab + symtab[i].st_name,
                      length);
            count ++;
        }

        /* get priority & stack size params*/
        rt_uint32_t flag = 0;
        rt_uint16_t priority;
        rt_uint32_t stacksize;

        // 这里仍然是.dynsym section的遍历
        for (i = 0; i < shdr[index].sh_size / sizeof(Elf_Sym); i++)
        {

            // 查找符号dlmodule_thread_priority，如果有这个符号，那么修改优先级，没有则使用默认优先级，找到一个就不再继续找
            if (((flag & 0x01) == 0) &&
                (rt_strcmp((const char *)(strtab + symtab[i].st_name), "dlmodule_thread_priority") == 0))
            {
                flag |= 0x01;
                priority = *(rt_uint16_t*)(module->mem_space + symtab[i].st_value - module->vstart_addr);
                if (priority < RT_THREAD_PRIORITY_MAX)
                {
                    module->priority = priority;
                }
            }

            // 查找符号dlmodule_thread_stacksize，如果有这个符号，那么修改栈大小，没有则使用默认栈大小，找到一个就不再继续找
            if (((flag & 0x02) == 0) &&
                (rt_strcmp((const char *)(strtab + symtab[i].st_name), "dlmodule_thread_stacksize") == 0))
            {
                flag |= 0x02;
                stacksize = *(rt_uint32_t*)(module->mem_space + symtab[i].st_value - module->vstart_addr);
                if ((stacksize < 2048) || (stacksize > 1024 * 32))
                {
                    module->stack_size = stacksize;
                }
            }

            // 两个都查找到后，就跳出循环
            if ((flag & 0x03) == 0x03)
            {
                break;
            }
        }
    }

    return RT_EOK;
}

rt_err_t dlmodule_load_relocated_object(struct rt_dlmodule* module, void *module_ptr)
{
    rt_ubase_t index, rodata_addr = 0, bss_addr = 0, data_addr = 0;
    rt_ubase_t module_addr = 0, module_size = 0;
    rt_uint8_t *ptr, *strtab, *shstrab;

    /* get the ELF image size */
    for (index = 0; index < elf_module->e_shnum; index ++)
    {
        /* text */
        if (IS_PROG(shdr[index]) && IS_AX(shdr[index]))
        {
            module_size += shdr[index].sh_size;
            module_addr = shdr[index].sh_addr;
        }
        /* rodata */
        if (IS_PROG(shdr[index]) && IS_ALLOC(shdr[index]))
        {
            module_size += shdr[index].sh_size;
        }
        /* data */
        if (IS_PROG(shdr[index]) && IS_AW(shdr[index]))
        {
            module_size += shdr[index].sh_size;
        }
        /* bss */
        if (IS_NOPROG(shdr[index]) && IS_AW(shdr[index]))
        {
            module_size += shdr[index].sh_size;
        }
    }

    /* no text, data and bss on image */
    if (module_size == 0) return RT_NULL;

    module->vstart_addr = 0;

    /* allocate module space */
    module->mem_space = rt_malloc(module_size);
    if (module->mem_space == RT_NULL)
    {
        LOG_E("Module: allocate space failed.\n");
        return -RT_ERROR;
    }
    module->mem_size = module_size;

    /* zero all space */
    ptr = module->mem_space;
    rt_memset(ptr, 0, module_size);

    /* load text and data section */
    for (index = 0; index < elf_module->e_shnum; index ++)
    {
        /* load text section */
        if (IS_PROG(shdr[index]) && IS_AX(shdr[index]))
        {
            rt_memcpy(ptr,
                      (rt_uint8_t *)elf_module + shdr[index].sh_offset,
                      shdr[index].sh_size);
            LOG_D("load text 0x%x, size %d", ptr, shdr[index].sh_size);
            ptr += shdr[index].sh_size;
        }

        /* load rodata section */
        if (IS_PROG(shdr[index]) && IS_ALLOC(shdr[index]))
        {
            rt_memcpy(ptr,
                      (rt_uint8_t *)elf_module + shdr[index].sh_offset,
                      shdr[index].sh_size);
            rodata_addr = (rt_uint32_t)ptr;
            LOG_D("load rodata 0x%x, size %d, rodata 0x%x", ptr,
                shdr[index].sh_size, *(rt_uint32_t *)data_addr);
            ptr += shdr[index].sh_size;
        }

        /* load data section */
        if (IS_PROG(shdr[index]) && IS_AW(shdr[index]))
        {
            rt_memcpy(ptr,
                      (rt_uint8_t *)elf_module + shdr[index].sh_offset,
                      shdr[index].sh_size);
            data_addr = (rt_uint32_t)ptr;
            LOG_D("load data 0x%x, size %d, data 0x%x", ptr,
                shdr[index].sh_size, *(rt_uint32_t *)data_addr);
            ptr += shdr[index].sh_size;
        }

        /* load bss section */
        if (IS_NOPROG(shdr[index]) && IS_AW(shdr[index]))
        {
            rt_memset(ptr, 0, shdr[index].sh_size);
            bss_addr = (rt_uint32_t)ptr;
            LOG_D("load bss 0x%x, size %d", ptr, shdr[index].sh_size);
        }
    }

    /* set module entry */
    module->entry_addr = (rt_dlmodule_entry_func_t)((rt_uint8_t *)module->mem_space + elf_module->e_entry - module_addr);

    /* handle relocation section */
    for (index = 0; index < elf_module->e_shnum; index ++)
    {
        rt_ubase_t i, nr_reloc;
        Elf_Sym *symtab;
        Elf_Rel *rel;

        #if (defined(__arm__) || defined(__i386__) || (__riscv_xlen == 32))
        if (!IS_REL(shdr[index]))
            continue;
        #elif (defined(__aarch64__) || defined(__x86_64__) || (__riscv_xlen == 64))
        if (!IS_RELA(shdr[index]))
            continue;
        #endif


        /* get relocate item */
        rel = (Elf_Rel *)((rt_uint8_t *)module_ptr + shdr[index].sh_offset);

        /* locate .dynsym and .dynstr */
        symtab   = (Elf_Sym *)((rt_uint8_t *)module_ptr +
                                 shdr[shdr[index].sh_link].sh_offset);
        strtab   = (rt_uint8_t *)module_ptr +
                   shdr[shdr[shdr[index].sh_link].sh_link].sh_offset;
        shstrab  = (rt_uint8_t *)module_ptr +
                   shdr[elf_module->e_shstrndx].sh_offset;
        nr_reloc = (rt_uint32_t)(shdr[index].sh_size / sizeof(Elf_Rel));

        /* relocate every items */
        for (i = 0; i < nr_reloc; i ++)
        {
            #if (defined(__arm__) || defined(__i386__) || (__riscv_xlen == 32))
            Elf_Sym *sym = &symtab[ELF32_R_SYM(rel->r_info)];
            #elif (defined(__aarch64__) || defined(__x86_64__) || (__riscv_xlen == 64))
            Elf_Sym *sym = &symtab[ELF64_R_SYM(rel->r_info)];
            #endif

            LOG_D("relocate symbol: %s", strtab + sym->st_name);

            if (sym->st_shndx != STN_UNDEF)
            {
                Elf_Addr addr = 0;

                if ((ELF_ST_TYPE(sym->st_info) == STT_SECTION) ||
                    (ELF_ST_TYPE(sym->st_info) == STT_OBJECT))
                {
                    if (rt_strncmp((const char *)(shstrab +
                                                  shdr[sym->st_shndx].sh_name), ELF_RODATA, 8) == 0)
                    {
                        /* relocate rodata section */
                        LOG_D("rodata");
                        addr = (Elf_Addr)(rodata_addr + sym->st_value);
                    }
                    else if (rt_strncmp((const char *)
                                        (shstrab + shdr[sym->st_shndx].sh_name), ELF_BSS, 5) == 0)
                    {
                        /* relocate bss section */
                        LOG_D("bss");
                        addr = (Elf_Addr)bss_addr + sym->st_value;
                    }
                    else if (rt_strncmp((const char *)(shstrab + shdr[sym->st_shndx].sh_name),
                                        ELF_DATA, 6) == 0)
                    {
                        /* relocate data section */
                        LOG_D("data");
                        addr = (Elf_Addr)data_addr + sym->st_value;
                    }

                    if (addr != 0) dlmodule_relocate(module, rel, addr);
                }
                else if (ELF_ST_TYPE(sym->st_info) == STT_FUNC)
                {
                    addr = (Elf_Addr)((rt_uint8_t *) module->mem_space - module_addr + sym->st_value);

                    /* relocate function */
                    dlmodule_relocate(module, rel, addr);
                }
            }
            else if (ELF_ST_TYPE(sym->st_info) == STT_FUNC)
            {
                /* relocate function */
                dlmodule_relocate(module, rel,
                                       (Elf_Addr)((rt_uint8_t *)
                                                    module->mem_space
                                                    - module_addr
                                                    + sym->st_value));
            }
            else
            {
                Elf_Addr addr;

                if (ELF32_R_TYPE(rel->r_info) != R_ARM_V4BX)
                {
                    LOG_D("relocate symbol: %s", strtab + sym->st_name);

                    /* need to resolve symbol in kernel symbol table */
                    addr = dlmodule_symbol_find((const char *)(strtab + sym->st_name));
                    if (addr != (Elf_Addr)RT_NULL)
                    {
                        dlmodule_relocate(module, rel, addr);
                        LOG_D("symbol addr 0x%x", addr);
                    }
                    else
                        LOG_E("Module: can't find %s in kernel symbol table",
                                   strtab + sym->st_name);
                }
                else
                {
                    addr = (Elf_Addr)((rt_uint8_t *) module->mem_space - module_addr + sym->st_value);
                    dlmodule_relocate(module, rel, addr);
                }
            }

            rel ++;
        }
    }

    return RT_EOK;
}
