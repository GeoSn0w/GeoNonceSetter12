//
//  osirisJailbreak.h
//  GeoSetter
//
//  Created by GeoSn0w on 8/24/19.
//  Copyright © 2019 GeoSn0w. All rights reserved.
//

#ifndef osirisJailbreak_h
#define osirisJailbreak_h

#include <stdio.h>
#include <mach/mach_types.h>

int initOsiris(task_port_t tzero);
void executeCommandAtFuckingPath(const char* path, int argc, ...);
void nvram_lockback_func(void);
int deinitOsiris(void);

#endif /* osirisJailbreak_h */
