# Keytray

macOS 菜单栏两步验证器(TOTP/HOTP):托盘常驻、键盘友好、本地存储。

基于 [mygo](https://github.com/egoist/mygo) 原生 UI 框架,零 cgo,交叉编译免配置。

## 功能

- **托盘面板**:点击托盘图标弹出验证码列表,点击行或 `⇧⌘0-9` 复制;集中倒计时,临近过期变红
- **全局快捷键**:`⌥Space` 唤起面板、`⌥S` 截屏导入(被占用自动降级备选,设置内可换)
- **多路导入**:截屏框选(一次识别全部二维码)/ 本地图片 / 粘贴 `otpauth://` / **Google Authenticator 迁移链接**(一条 `otpauth-migration://` 批量导入)/ 加密备份文件
- **本地加密(可选,默认关)**:设置主密码后 AES-256-GCM + Argon2id 加密金库;可选钥匙串自动解锁(启动免输);自动锁定、复制后 30 秒清剪贴板
- **账号管理**:搜索、拖拽排序 / ↑↓ 排序、编辑全部 OTP 参数、按服务分组(粘性分组头)
- **算法**:TOTP/HOTP 全参数(SHA1/256/512、6/8 位、自定义周期、HOTP 计数器)、Steam Guard(issuer=Steam)
- **导出**:加密备份(独立密码)、明文 CSV(含 otpauth:// 列,加密模式需主密码确认)
- **HTTP 取码接口**(默认关):`GET http://127.0.0.1:17304/codes?token=…` 返回 JSON;仅本机监听、随机令牌鉴权、锁定时不吐码

## 构建与运行

```bash
go run .                 # 开发运行(菜单栏出现图标)
go run ./cmd/devseed -vault "$HOME/Library/Application Support/Keytray/vault.kt" \
  -password demo-password \
  'otpauth://totp/GitHub:feyman?secret=JBSWY3DPEHPK3PXP'
go tool mygo build -skip-notarize   # 产出 build/darwin-arm64/Keytray.app + dmg
GOOS=windows go build -o keytray.exe .   # Windows 交叉编译
```

## 平台状态与系统要求

| 平台 | 最低系统版本 | 芯片 | 产物 | 状态 |
|---|---|---|---|---|
| macOS | **12.0 Monterey**(mygo 框架要求) | Universal(Apple Silicon + Intel 同包) | .dmg | ✅ 完整功能,日常使用中 |
| Windows | **10**(11 上有圆角/透明加成) | amd64(ARM 设备走系统模拟层) | .exe | ⚠️ 编译通过;全屏识别导入可用,框选交互与实机验收待续 |
| Linux | 无硬性版本(静态二进制) | amd64 + arm64 | 裸二进制 | ⚠️ 编译通过;需图形桌面 + 任一截屏工具(gnome-screenshot/spectacle/import),实机验收待续 |

功能分层说明(macOS):核心功能 12.0 即可;开机自启在 13+ 走系统登录项、12 上自动降级为 launch agent。

## CI/CD(GitHub Actions)

推送自动跑测试;打 `v*` tag 自动构建三平台并发布 Release(macOS 为 universal dmg)。无需自备 runner。

## 安全模型

- 金库为单文件(`Application Support/Keytray/vault.kt`),格式按文件头自动识别:加密(`KTVAULT` + Argon2id 参数 + AES-256-GCM)或明文 JSON(未开启加密时)
- **主密码无任何找回通道**:丢失即数据不可恢复;请定期导出加密备份
- 不联网;HTTP 接口默认关闭且仅监听本机
- 需求基线与设计决策详见 [REQUIREMENTS.md](REQUIREMENTS.md)

## 开发

```bash
CGO_ENABLED=0 go test ./...   # 全部测试
go tool mygo vet .            # mygo UI 规则检查
```
