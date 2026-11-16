# MFA 移植验证记录

环境：Windows 工作区，FedoraLinux-43 WSL；Rust/Cargo 1.99.1，russh 0.61.2。
测试只使用临时配置、生成的密钥和 loopback SSH 服务，不读取真实凭据。

| 场景 | 证据 | 结果 |
|---|---|---|
| A1 连续 MFA、普通认证和 Agent | 生产认证代码的协议 fixture；Agent 提供两把测试密钥，首把 partial success 后直接 MFA | 通过 |
| A2 错码、取消、无 UI、断线、16 轮上限 | fixture 的协议用例；UI 失效挑战清理 | 通过 |
| A3 共享 SFTP、custom/sudo、取消 channel、拒绝 SFTP | 生产通道代理和 elevation 层在活跃 PTY 上测试；关闭文件 channel 后继续回显 | 通过 |
| A4 管理器新增/编辑/删除/引用、倒计时 | 软件渲染 UI 测试、会话草稿往返；已查看渲染图，密钥编辑框为空且布局完整 | 通过 |
| A5 自动 OTP 和手动输入 | RFC 6238 SHA1/SHA256/SHA512 向量；混合/公共 banner/菜单/删除条目回退；Password 标题及 New password 不误填 | 通过 |
| A6 存储与导入导出隔离 | 密文保存、解密、损坏密文保留、删除清引用、失败回滚；导入不能绑定本机条目或替换其密钥 | 通过 |
| A7 当前行为回归 | 共享凭据 16 项、导入相关 27 项、传输槽相关 7 项 | 通过 |

执行命令和结果：

- `cargo test --locked --manifest-path tests/ssh_auth_fixture/Cargo.toml`：41 passed。
- `cargo test --locked --bin meatshell mfa`：6 passed，包含导入隔离新增用例。
- `cargo test --locked --test ui_auth_prompts`：5 passed，包含并发挑战和断线清理。
- `cargo test --locked --bin meatshell credential`：16 passed。
- `cargo test --locked --bin meatshell import`：27 passed。
- `cargo test --locked --bin meatshell slot`：7 passed，其中包含 3 项 SFTP 排队测试。
- `cargo check --locked`：完整 Linux 桌面代码和 Slint 编译通过。
- `cargo check --locked --features headless`：通过。
- `cargo check --locked --target x86_64-pc-windows-gnu`：通过。
- `git diff --check`：通过。

独立静态审查发现并修复了账号密码上下文误判、并发挑战合并和断线后
失效提示残留。追加的密码提示限制由协议反例和分类单测验证。

Windows 交叉检查首次因 `/tmp` 的 16 GiB tmpfs 写满而中断；编译缓存已
迁至磁盘，并在原路径保留链接后重新检查通过。编译存在未使用项警告。
自动化未实际连接真实堡垒机，也未读取或填写用户 MFA 密钥。

## Windows 部署

- `cargo build --locked --release --target x86_64-pc-windows-gnu` 通过，
  耗时 5 分 17 秒；使用 MinGW 链接并嵌入图标、DPI manifest 和版本资源。
- 运行时版本为 `meatshell 0.8.3`，Windows 产品版本为 `0.8.3-mfa.20261116`。
- 安装在 `%LOCALAPPDATA%/Programs/MeatShell-0.8.3-MFA-20261116`，
  沿用原配置目录，并备份配置和原快捷方式；安装时原有 18 个进程均保留。
- 桌面和开始菜单的“MeatShell MFA 测试版”快捷方式已指向新版。
- 安装文件与构建产物的 SHA-256 一致：
  `BF99212EB3D32044FB2562D4C78EB1D781BFCA20FFE7BC9D59BBFD2AEA9DCF29`。
- Windows 上完成版本及配置加载检查；重新启动后窗口正常响应，
  已通过原生 UI 核对设置菜单包含“MFA 管理”。用户随后反馈“已经修复了”。
- 提交前再次比较构建输入摘要，当前产品代码与通过测试并部署的代码一致。
