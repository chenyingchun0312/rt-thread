/*
 * Copyright (c) 2006-2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018/08/11     Bernard      the first version
 */

#ifndef RT_DL_MODULE_H__
#define RT_DL_MODULE_H__

#include <rtthread.h>

#define RT_DLMODULE_STAT_INIT       0x00
#define RT_DLMODULE_STAT_RUNNING    0x01
#define RT_DLMODULE_STAT_CLOSING    0x02
#define RT_DLMODULE_STAT_CLOSED     0x03

struct rt_dlmodule;
typedef void* rt_addr_t;

typedef void (*rt_dlmodule_init_func_t)(struct rt_dlmodule *module);
typedef void (*rt_dlmodule_cleanup_func_t)(struct rt_dlmodule *module);
typedef int  (*rt_dlmodule_entry_func_t)(int argc, char** argv);

struct rt_dlmodule
{
    struct rt_object parent;
    rt_list_t object_list;  /* objects inside this module */

    rt_uint8_t stat;        /* status of module */

    /* rt-thread在装一个elf格式文件时，会自动为它创建一个线程来执行它,下面就是该线程的几个属性 */
    rt_uint16_t priority;                   /* 模块的线程优先级 */
    rt_uint32_t stack_size;                 /* 模块的线程栈大小 */
    struct rt_thread *main_thread;          /* 模块的线程控制块 */
    
    /* the return code */
    int ret_code;

    rt_uint32_t vstart_addr;                /* ELF文件中，第一个可加载段的起始地址 */

    rt_dlmodule_entry_func_t  entry_addr;   /* 当前模块执行指令的入口地址，如果是动态链接库，则为NULL */
    char *cmd_line;                         /* command line */

    rt_addr_t   mem_space;                  /* ELF文件中，需要加载到内存中的段（数据+指令），保存到该区域 */
    rt_uint32_t mem_size;                   /* ELF文件中，加载到内存中的段（数据+指令）的长度 */

    rt_dlmodule_init_func_t     init_func;  /* 在执行模块的入口地址前，调用的函数，可以做一些初始化操作 */
    rt_dlmodule_cleanup_func_t  cleanup_func;/*在执行完模块后，调用的函数，可以做一些清理工作 */

    rt_uint16_t nref;                       /* 当前模块被引用（open）的次数 */

    rt_uint16_t nsym;                       /* 当前模块中，使用到的外部符号（这里指函数）的个数 */
    struct rt_module_symtab *symtab;        /* 当前模块中，使用到的外部符号（这里指函数）的表单 */
};

struct rt_dlmodule_ops
{
    rt_uint8_t *(*load)(const char* filename);  /* load dlmodule file data */
    rt_err_t (*unload)(rt_uint8_t *param);  /* unload dlmodule file data */
};

struct rt_dlmodule *dlmodule_create(void);
rt_err_t dlmodule_destroy(struct rt_dlmodule* module);

struct rt_dlmodule *dlmodule_self(void);

struct rt_dlmodule *dlmodule_load(const char* pgname);
struct rt_dlmodule *dlmodule_exec(const char* pgname, const char* cmd, int cmd_size);

#if defined(RT_USING_CUSTOM_DLMODULE)
struct rt_dlmodule* dlmodule_load_custom(const char* filename, struct rt_dlmodule_ops* ops);
struct rt_dlmodule* dlmodule_exec_custom(const char* pgname, const char* cmd, int cmd_size, struct rt_dlmodule_ops* ops);
#endif

void dlmodule_exit(int ret_code);

struct rt_dlmodule *dlmodule_find(const char *name);

rt_uint32_t dlmodule_symbol_find(const char *sym_str);

#endif
