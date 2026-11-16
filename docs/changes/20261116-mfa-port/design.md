# MFA 移植方案

通过历史提交 `e57b587` 与参考目录比较，提取 MFA 改动；跳过参考目录中
删除本地终端配置、收窄工具栏间距等无关差异。现有共享凭据、Agent、
RSA 签名协商和 SFTP 传输队列与移植代码合并。

认证集中到 `ssh/impls/authentication.rs`。密码和私钥使用 russh 0.61
的最终认证结果；Agent 遇到 partial success 停止尝试其他密钥，继续 MFA。
密钥密码短语和 Agent 会话的密码字段不能成为远端挑战响应或 sudo 密码。
普通密码认证成功则直接返回，例如无 MFA 的密码服务器不弹验证码框。

GUI SFTP 通过终端命令队列申请独立 channel，文件读写不持有终端 Handle
锁；只关闭自己的文件通道。CLI/MCP 继续支持独立连接和既有授权限制。
例如堡垒机拒绝 SFTP 时，已认证终端仍可使用，且不回退新连接。

TOTP 复用现有 Secret 和本机加密。配置采用带默认值的新字段；自动应答
只识别实际 prompt，避免公共 OTP banner 导致密码或菜单被误填。
例如 `Verification code:` 可自动填码，`Password:`、可回显字段和菜单
仍走原有人工/密码处理。管理入口位于设置菜单，会话编辑可选择条目。

账号密码仅自动应答标准密码提示；说明文字中的 Password 不会触发自动
填写，`New password:` 和数据库密码等其他字段交给用户。MFA 队列按挑战
分别排队，不合并同一保存会话的不同连接；通过 oneshot 接收端状态清理
已经结束的挑战，避免断线弹窗残留或把旧输入发给重连后的请求。

russh 0.61.2 已包含旧参考补丁中的认证状态刷新与关闭通道报错，但仍在
人工应答期间阻塞 transport loop。保留 0.61.2，vendor 修复挑战派发和
响应编码，不移植 0.49.2。补丁边界见 `vendor/russh/MEATSHELL_PATCH.md`。

验证包括生产认证/通道代码的 loopback 协议 fixture、配置和 TOTP 单测、
管理器 UI 测试，以及完整桌面和 headless 编译。真实堡垒机策略由后续
实际连接验证；本次不接触真实凭据。结果记录在本目录 verification.md。
