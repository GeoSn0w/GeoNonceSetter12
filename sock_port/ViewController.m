//
//  ViewController.m
//  sock_port
//
//  Created by Jake James on 7/17/19.
//  Copyright © 2019 Jake James. All rights reserved.
//

#import "ViewController.h"
#include "exploit.h"
#include "osirisJailbreak.h"
#include <string.h>
#include "log.h"
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
