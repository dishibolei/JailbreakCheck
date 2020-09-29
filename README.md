# JailbreakCheck

用于做越狱检测。可以直接引用UserCust文件即可。类名做了简单混淆，如果有需要可以再混淆。

用于越狱检测的方法：

```
[[UserCust sharedInstance] UVItinitse];
```

如果要禁止gdb调试，可以使用：

```
[[UserCust sharedInstance] disable_gdb]
```

