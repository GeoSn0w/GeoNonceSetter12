//
//  osirisJailbreak.h
//  sock_port
//
//  Created by GeoSn0w on 8/20/19.
//  Copyright © 2019 Jake James. All rights reserved.
//

#ifndef osirisJailbreak_h
#define osirisJailbreak_h

#include <stdio.h>
#include <mach/mach_types.h>

int initOsiris(task_port_t tzero);
void executeCommandAtFuckingPath(const char* path, int argc, ...);
int deinitOsiris(void);

#endif /* osirisJailbreak_h */
