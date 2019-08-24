//
//  ViewController.m
//  GeoSetter
//
//  Created by GeoSn0w on 8/24/19.
//  Copyright © 2019 GeoSn0w. All rights reserved.
//

#import "ViewController.h"
#include "exploit.h"
#include "osirisJailbreak.h"
#include <string.h>
#include "log.h"
#include <stdio.h>
#include <stdbool.h>
#include <mach/machine.h>

//For iOS version detection
#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
   
}

-(void)viewDidAppear:(BOOL)animated{
     [self deviceSanityCheck]; //Ensure it's not A12...
}
-(void) deviceSanityCheck{
    struct platform {
        const char machine[32];
        const char osversion[32];
        cpu_type_t cpu_type;
        cpu_subtype_t cpu_subtype;
        unsigned physical_cpu;
        unsigned logical_cpu;
        size_t page_size;
        size_t memory_size;
    };
    struct platform platform;
    struct utsname u = {};
    int error = uname(&u);
    assert(error == 0);
    strncpy((char *)platform.machine, u.machine, sizeof(platform.machine));
    
    mach_port_t host = mach_host_self();
    assert(MACH_PORT_VALID(host));
    host_basic_info_data_t basic_info;
    mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
    kern_return_t kr = host_info(host, HOST_BASIC_INFO, (host_info_t) &basic_info, &count);
    assert(kr == KERN_SUCCESS);
    
    platform.cpu_type     = basic_info.cpu_type;
    platform.cpu_subtype  = basic_info.cpu_subtype;
    mach_port_deallocate(mach_task_self(), host);
    // Log basic platform info.
    DEBUG_TRACE(1, "platform: %s %s", platform.machine, platform.osversion);
    
    
    if (strcmp(platform.machine,"iPhone11,1") == 0 || strcmp(platform.machine,"iPhone11,2") == 0 || strcmp(platform.machine,"iPhone11,3") == 0 || strcmp(platform.machine,"iPhone11,4") == 0 || strcmp(platform.machine,"iPhone11,5") == 0 || strcmp(platform.machine,"iPhone11,6") == 0 || strcmp(platform.machine,"iPhone11,8") == 0 || strcmp(platform.machine,"iPhone11,9") == 0 || strcmp(platform.machine,"iPad11,3") == 0 || strcmp(platform.machine,"iPad11,4") == 0 || strcmp(platform.machine,"iPad11,1") == 0 || strcmp(platform.machine,"iPad11,2") == 0 || strcmp(platform.machine,"iPad8,1") == 0 || strcmp(platform.machine,"iPad8,2") == 0 || strcmp(platform.machine,"iPad8,3") == 0 || strcmp(platform.machine,"iPad8,4") == 0 || strcmp(platform.machine,"iPad8,5") == 0 || strcmp(platform.machine,"iPad8,6") == 0 || strcmp(platform.machine,"iPad8,7") == 0 || strcmp(platform.machine,"iPad8,8") == 0){
        UIAlertController * alert = [UIAlertController
                                     alertControllerWithTitle:@"STOP!"
                                     message:@"You are running the app on an incompatible device. A12 and A12X are not supported. Follow GeoSn0w (@FCE365) on Twitter or iDevice Central on YouTube to stay updated!"
                                     preferredStyle:UIAlertControllerStyleAlert];
        [self presentViewController:alert animated:YES completion:nil];
    }
}
- (IBAction)setNonceNow:(id)sender {
    [self.view endEditing:YES];
    if (SYSTEM_VERSION_LESS_THAN(@"12.0")) {
        UIAlertController * alert = [UIAlertController
                                     alertControllerWithTitle:@"STOP!"
                                     message:@"You are running an incompatible iOS version. Nonce cannot be set below 12.0 with this tool."
                                     preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* dismiss = [UIAlertAction
                                  actionWithTitle:@"Dismiss"
                                  style:UIAlertActionStyleDefault
                                  handler:^(UIAlertAction * action) {
                                      
                                  }];
        
        [alert addAction:dismiss];
        [self presentViewController:alert animated:YES completion:nil];
        _setNonceButton.enabled = false;
        _noncefield.enabled = false;
        return;
    } else if (SYSTEM_VERSION_GREATER_THAN(@"12.4")) {
        UIAlertController * alert = [UIAlertController
                                     alertControllerWithTitle:@"STOP!"
                                     message:@"You are running an incompatible iOS version. Nonce cannot be set above 12.4 currently."
                                     preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* dismiss = [UIAlertAction
                                  actionWithTitle:@"Dismiss"
                                  style:UIAlertActionStyleDefault
                                  handler:^(UIAlertAction * action) {
                                      
                                  }];
        
        [alert addAction:dismiss];
        [self presentViewController:alert animated:YES completion:nil];
        _setNonceButton.enabled = false;
        _noncefield.enabled = false;
        return;
    } else if (SYSTEM_VERSION_EQUAL_TO(@"12.3")) {
        UIAlertController * alert = [UIAlertController
                                     alertControllerWithTitle:@"STOP!"
                                     message:@"You are running an incompatible iOS version. Nonce cannot be set on 12.3 currently."
                                     preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* dismiss = [UIAlertAction
                                  actionWithTitle:@"Dismiss"
                                  style:UIAlertActionStyleDefault
                                  handler:^(UIAlertAction * action) {
                                      
                                  }];
        
        [alert addAction:dismiss];
        [self presentViewController:alert animated:YES completion:nil];
        _setNonceButton.enabled = false;
        _noncefield.enabled = false;
        return;
    } else if (SYSTEM_VERSION_EQUAL_TO(@"12.3.1")) {
        UIAlertController * alert = [UIAlertController
                                     alertControllerWithTitle:@"STOP!"
                                     message:@"You are running an incompatible iOS version. Nonce cannot be set on 12.3.1 currently."
                                     preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* dismiss = [UIAlertAction
                                  actionWithTitle:@"Dismiss"
                                  style:UIAlertActionStyleDefault
                                  handler:^(UIAlertAction * action) {
                                      
                                  }];
        
        [alert addAction:dismiss];
        [self presentViewController:alert animated:YES completion:nil];
        _setNonceButton.enabled = false;
        _noncefield.enabled = false;
        return;
    }
    NSString *nonce = _noncefield.text;
    if ([nonce length] == 0) {
        UIAlertController * alert = [UIAlertController
                                     alertControllerWithTitle:@"WARNING!"
                                     message:@"Nonce generator cannot be zero. Double check!"
                                     preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* dismiss = [UIAlertAction
                                  actionWithTitle:@"Dismiss"
                                  style:UIAlertActionStyleDefault
                                  handler:^(UIAlertAction * action) {
                                      
                                  }];
        
        [alert addAction:dismiss];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    if([nonce hasPrefix:@"0x"]) {
        printf("Nonce has 0x prefix!\n");
    } else {
        UIAlertController * alert = [UIAlertController
                                     alertControllerWithTitle:@"WARNING!"
                                     message:@"Your nonce should begin with 0x and have 16 digits after that. Yours lacks the 0x prefix. Double check!"
                                     preferredStyle:UIAlertControllerStyleAlert];
  
        UIAlertAction* dismiss = [UIAlertAction
                                   actionWithTitle:@"Dismiss"
                                   style:UIAlertActionStyleDefault
                                   handler:^(UIAlertAction * action) {
                                     
                                   }];
        
        [alert addAction:dismiss];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    [sender setTitle:@"Getting tfp0..." forState:UIControlStateNormal];
     dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void){
        char *const nonceConstPart = "com.apple.System.boot-nonce";
        mach_port_t tfp0 = get_tfp0();
        if (initOsiris(tfp0) == 0){
         
            executeCommandAtFuckingPath("/usr/sbin/nvram", 1, [NSString stringWithFormat:@"%s=%@", nonceConstPart, nonce].UTF8String, NULL);
            dispatch_async(dispatch_get_main_queue(), ^{
                  [sender setTitle:@"Setting..." forState:UIControlStateNormal];
            });
            sleep(1);
            executeCommandAtFuckingPath("/usr/sbin/nvram", 1, [NSString stringWithFormat:@"%s=%s", "IONVRAM-FORCESYNCNOW-PROPERTY", nonceConstPart].UTF8String, NULL);
    
            executeCommandAtFuckingPath("/usr/sbin/nvram", 1, "-p");
            deinitOsiris();
            dispatch_async(dispatch_get_main_queue(), ^{
                _setNonceButton.enabled = false;
                _noncefield.enabled = false;
                [sender setTitle:@"Done!" forState:UIControlStateDisabled];
                nvram_lockback_func();
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                _setNonceButton.enabled = false;
                _noncefield.enabled = false;
                [sender setTitle:@"tfp0 failure" forState:UIControlStateDisabled];
            });
        }
    });
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
