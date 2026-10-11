# AXP 解包工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python)

天龙八部（TLBB）客户端 AXP / XZIP 资源工程工具 —— 读出来、改得动、还能原样打回去。

> **本仓库只带源码与结论，不含客户端二进制，也不含任何游戏素材。**

---

## 功能

- **打开 / 导出**：单包秒开，也可全盘扫描；导出时自动解码解密（25 路 AXP 算法 + 脚本容器），改完能原样打回去
- **打包回 AXP**：选个改好的文件夹直接打回；条目变长走"搬家式"写入，名字表按规则自动维护
- **XZIP**：官方补丁包解包 / 打包；制作补丁(XZIP)
- **一键加解密**：自动认格式（脚本容器 / AXP 存储块 / LZMA 包裹），块相位用块头 CRC 自动对上，
  显示"校验对上 / 没对上"；支持单个文件，也支持**整个文件夹批量**（保持目录结构，没加密的文件原样搬）
- 原生窗口（pywebview 套本机 Flask 后端），数据不出本机

## 运行环境

- Python 3.13（实测 3.13.5，Windows x64）
- 依赖：flask、pywebview

```
pip install -r requirements.txt
python server.py
```

Windows 也可以直接双击 `启动.bat`。默认数据目录 `D:\XTLBB\Data`，界面上可改。

## 打包成 exe

```
pip install pyinstaller
pyinstaller AXP解包工具.spec
```

产物在 `dist\AXP解包工具.exe`（单文件，约 51 MB，双击即用）。

## 源码构成

| 文件 | 说明 |
| --- | --- |
| `server.py` | 后端与入口：Flask 路由、pywebview 窗口、原生文件对话框 |
| `axp-tool.html` | 前端界面（单文件） |
| `axpcore.py` | AXP 容器：读取 / 统计 / 导出 / 形态识别 |
| `packcore.py` | 回包：AXP 重打包、XZIP 补丁、写后自检 |
| `scriptcodec.py` | 脚本容器（Lua 容器头 / 正文） |
| `axpcodex.py` | 25 路算法编解码快速路径（配 `axp_tables.bin`） |
| `axp_build.py` | 名字表 / 哈希表 / CRC 权威实现 |
| `axp_tables.bin` | 密钥表（4 KB），必须与源码同目录 |
| `AXP解包工具.spec` | PyInstaller 打包配置 |
| `icon.ico` | 程序图标 |

## 版本与验证

- 2026-10-11：与发布包 v6 同源（exe md5 `94ba55d84bbe67c760ba88e6974de06b`）。
- 独立副本实测：后端测试 76 项全过（含混合目录 13 个文件整体加密回去逐字节还原）；
  冒烟：打开 Model4.axp → 54 条、导出 54 个文件 0 错误。详见 `自检记录.txt`。

---

## 免责声明

- 本项目是**非官方、未授权**的第三方互操作性研究工具，与游戏开发商、发行商及任何运营方
  **均无关联、均未获其认可**。
- 仓库**不包含**游戏客户端、`Data/*.axp`、模型 / 贴图 / 音频等任何游戏素材，也**不提供**
  获取途径。使用者需自行准备合法取得的客户端，并自行承担相应责任。
- 唯一随仓库分发的客户端派生数据是 `axp_tables.bin`（4 KB 密钥表）：它是解码容器所必需的
  **功能性互操作性常量**，不含任何美术作品。
- 格式知识来自对本地客户端的合法研究，仅用于**理解与互操作性**目的。**请勿**用本项目
  分发游戏素材，也请勿用于商业运营服务端。
- 游戏名称、资源名与商标归其各自权利人所有。

## License

[MIT](LICENSE) —— 可自由使用、修改、分发、商用，保留版权声明即可。
