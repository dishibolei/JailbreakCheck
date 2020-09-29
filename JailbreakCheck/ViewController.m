//
//  ViewController.m
//  JailbreakCheck
//
//  Created by 卜磊 on 2020/9/27.
//

#import "ViewController.h"
#import "UserCust.h"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UILabel *textLabel;

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view.
}

- (IBAction)checkJailBreak:(id)sender {
  BOOL jail = [[UserCust sharedInstance] UVItinitse];
  self.textLabel.text = jail ? @"已越狱" : @"未越狱";
}

@end
