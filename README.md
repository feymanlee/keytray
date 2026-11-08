<div align="center">

<h1>
  <img src="resources/icon.png" alt="Keytray Logo" width="96" height="96"><br>
  Keytray
</h1>

### 两步验证码，常驻系统托盘。

**TOTP/HOTP 全参数。截图导入二维码。本地加密，离线运行。**<br>
<kbd>Alt+Space</kbd> 唤起面板，<kbd>Alt+S</kbd> 截图导入，点击账号行复制。<br>
三十秒过后，验证码自动更新。

[![ci](https://github.com/feymanlee/keytray/actions/workflows/ci.yml/badge.svg)](https://github.com/feymanlee/keytray/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/feymanlee/keytray?label=release&color=111111)](https://github.com/feymanlee/keytray/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-111111)](LICENSE)<br>
![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D4?logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)

**[Download](https://github.com/feymanlee/keytray/releases)** &nbsp;·&nbsp; **[需求基线](REQUIREMENTS.md)** &nbsp;·&nbsp; **[License](LICENSE)**

<!-- TODO：首屏截图（浅色、深色托盘面板各一张），拿到后嵌入此处 -->

</div>

<br>

## Keytray 适合你吗？

验证码散落在手机验证器里，换机要一个个迁、截图要一张张拍、抄写要眯眼看 0 和 6。Keytray 把这些放进系统托盘：

- **点一下就复制**：点击账号行，验证码直接进剪贴板，30 秒后自动清空。
- **截图即导入**：macOS 可框选屏幕区域，Windows/Linux 自动识别全屏二维码；Google Authenticator 的迁移链接、本地图片、`otpauth://` 文本、加密备份，四条路都能进。
- **密钥只属于你**：使用 AES-256-GCM + Argon2id 加密金库（可选，默认明文），不联网、无云同步、无找回后门；主密码丢失即数据不可恢复。
- **算法不挑食**：支持 TOTP/HOTP 全参数（SHA1/256/512、6/8 位、自定义周期）、Steam Guard、GA 迁移格式。
- **给开发者留了门**：本地 HTTP 接口（默认关闭，仅监听 127.0.0.1，并使用令牌鉴权），脚本一行 `curl` 拿码。

如果你只需要在手机上看码，手机验证器就够。如果你要在电脑上登录、要在多台设备间迁移、受够了眯眼抄码——那就是 Keytray。

Keytray 运行在 macOS（12+）、Windows（10+）和 Linux 上，常驻系统托盘，零 CGO。

## 快速开始

**1 · 安装。** 从 [Releases](https://github.com/feymanlee/keytray/releases) 选择对应平台的产物：

- macOS：DMG 安装包，内含 `.app`
- Windows：`.exe` 可执行文件
- Linux：对应架构的裸二进制

也可以本地构建：

```sh
go tool mygo build -skip-notarize                    # macOS：.app + DMG
GOOS=windows GOARCH=amd64 go build -o keytray.exe .  # Windows
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o keytray .
```

**2 · 加一个账号。** 点系统托盘图标 → **添加**（或按 <kbd>A</kbd>），填写服务名、账号名和密钥；或者按 <kbd>Alt+S</kbd> 开始截图导入。从 Google Authenticator 迁移：截取导出的迁移二维码即可，一条链接搬全部。

**3 · （可选）开启本地加密。** 设置 → 本地加密 → 设置主密码。之后可以开启「启动时自动解锁」（使用系统凭据存储）。⚠️ 主密码丢失无法找回，请定期导出加密备份。

**4 · 复制使用。** <kbd>Alt+Space</kbd> 唤起，搜索过滤，点击复制——30 秒后剪贴板自动清空，面板自动收起。

## 功能

- **托盘面板**：验证码 3+3 分组、集中倒计时、临近过期变红、悬停查看全名
- **多路导入**：截屏框选（多码）、本地图片、`otpauth://`、GA 迁移链接、加密备份
- **多账号管理**：搜索、拖拽排序、编辑全部参数、按服务分组、管理模式（✎ ↑ ↓ 🗑）
- **导出**：加密备份（独立密码）、明文 CSV（包含 `otpauth://` 列，带二次确认）
- **开发者接口**：`GET /codes?token=…`（JSON），锁定时返回 423

## 平台支持

| 平台 | 最低系统 | 托盘与截图导入 | 产物 | 状态 |
|---|---|---|---|---|
| macOS | 12.0 Monterey | 菜单栏；支持区域截图 | `.dmg` | ✅ 完整功能，日常使用中 |
| Windows | 10 | 通知区域；全屏识别二维码 | `.exe` | ⚠️ 已完成编译验证，真实设备验收待续 |
| Linux | 需要图形桌面 | AppIndicator；全屏识别二维码 | 裸二进制 | ⚠️ 已完成编译验证，真实桌面验收待续 |

截图导入在不同平台上的行为：

- **macOS**：使用系统区域选择器，需要在“系统设置 → 隐私与安全性 → 屏幕与系统音频录制”中允许 Keytray。
- **Windows**：抓取整个虚拟屏幕并识别其中的二维码，暂不提供 macOS 式框选。
- **Linux**：抓取整个屏幕并依次尝试 `gnome-screenshot`、KDE `spectacle` 或 ImageMagick `import`，需要系统预装其中一个工具。

开机自启、剪贴板、全局快捷键、单实例和系统凭据存储由各平台的 MyGo 后端提供。快捷键默认是 <kbd>Alt+Space</kbd> 唤起面板、<kbd>Alt+S</kbd> 截图导入，也可以在设置中修改。

## 安全模型

- 金库 = 系统用户数据目录中的单文件（macOS 示例：`Application Support/Keytray/vault.kt`），按文件头自动识别：加密（`KTVAULT` + Argon2id + AES-256-GCM）或明文 JSON
- **不联网**；HTTP 接口默认关闭，仅限本机访问并使用令牌鉴权，锁定时不返回验证码
- 无恢复后门：主密码丢失即数据不可恢复，定期导出加密备份是唯一保险

## 开发

```sh
CGO_ENABLED=0 go test ./...   # 全部测试
go tool mygo vet .            # mygo UI 规则检查
go run ./cmd/devseed -vault /tmp/vault.kt -password demo-password \
  'otpauth://totp/GitHub:feyman?secret=JBSWY3DPEHPK3PXP'
```

需求基线与设计决策见 [REQUIREMENTS.md](REQUIREMENTS.md)。

## License

[MIT](LICENSE)
