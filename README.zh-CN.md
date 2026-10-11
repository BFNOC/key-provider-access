# CPA Key Provider Access

[English](README.md) · 简体中文

`key-provider-access` 是一个本地 CLIProxyAPI 插件，布局和管理界面源自 `key-model-access` v0.1.3。插件沿用 CPA 内置的下游 API Key 认证，按 Key 对上游凭证配置（以下简称「上游配置」）设置允许和拒绝规则，而不是按模型名限制。

上游配置包括 OAuth 凭证和基于 API Key 的供应商。策略只保存 CPA 的稳定 auth ID，不保存 OAuth token 或上游 API Key。

## 关于此 fork

此仓库 fork 自 [GLGDLY/key-provider-access](https://github.com/GLGDLY/key-provider-access)，新增以下改动：

- 支持读取 CPA Manager Plus 的 `enc::v2` 浏览器会话，设置页可以在 CPAMP 完整模式和 CPAMP 轻量面板下使用。
- 白名单失败即关闭：即使允许的上游配置不可用或 ID 发生变化，Key 也不会被转到白名单之外的上游配置。
- 拒绝记录常驻显示在设置页、状态接口和 CPA 进程日志中。
- 设置页不会自行添加、移除或恢复任何规则。

## 从此 fork 安装

在 CPA 配置中把此 fork 的 registry 添加为插件商店源：

```yaml
plugins:
  store-sources:
    - "https://raw.githubusercontent.com/BFNOC/key-provider-access/main/registry.json"
```

然后在插件商店中从 BFNOC 源安装 `key-provider-access`。CPA 不允许把已安装的插件切换到另一个商店源，因此如果已从官方商店安装，需要先卸载。卸载前先备份 `plugins/key-provider-access/config.toml`；设置页初始化存储时会沿用已有文件。

## 行为

- CPA 认证下游 Key 后提供 `Metadata.caller_scope`。
- 没有策略的 Key 可以使用所有符合条件的上游配置。
- `deny_profiles` 优先于 `allow_profiles`。
- 非空的 `allow_profiles` 是白名单。
- 空的 `allow_profiles` 允许所有未被 `deny_profiles` 匹配的上游配置。
- `*` 匹配任意数量的字符，`?` 匹配一个字符。
- 调度器只在允许的候选中选择，并对符合条件的候选轮询。
- 如果 CPA 给出的候选都不匹配非空的白名单，请求会被拒绝。以下情况都属于此类：允许的上游配置正在冷却、已禁用、被另一个优先级档位压过，或者因为修改了 API Key、base URL、proxy URL、prefix、headers 或供应商名称而导致 ID 变化。插件不会用其他上游配置代替。
- 每次拒绝都会记录到状态接口的 `runtime_warning` 和 `runtime_warning_detail` 字段，并显示在设置页概览中，内容包括 Key 指纹、provider、model、CPA 给出的候选 ID（邮箱已打码）、次数和时间。记录会一直保留，直到保存或重载策略。每个 Key、provider 和 model 组合第一次被拒时，还会向 CPA 进程日志写一行。
- 设置页不会自行添加、移除或恢复任何规则。引用的上游配置已不在目录中的规则会保留在策略里，并在提示中计数；允许的上游配置全部消失的 Key 会保持拒绝状态，并持续被标出，直到管理员选择替代的上游配置。
- 在设置页中取消某个 Key 的最后一个允许项时，会设置 `deny_profiles = ["*"]`，而不是留下空的白名单，因为空白名单表示允许全部。
- CPA v7.2.146 之前格式的 Gemini、Gemini Interactions、Claude、Codex 和 xAI API Key 上游配置 ID，会借助临时属性与当前候选匹配。这样在 CPA 更换 ID 格式后，已有的允许和拒绝规则仍然有效，同时不会持久化凭证，也不会悄悄放行另一个 Key。
- after-auth 拦截器会在上游执行器收到请求之前，校验所选的 auth ID。
- 只要存在任何策略，缺少身份、缺少所选 auth 元数据或策略状态无效时，都会拒绝请求。

## 兼容性说明

- **优先级档位。** 调度器收到的是 CPA 当前符合条件的最高优先级候选档位。白名单不能把 CPA 没有给出的较低优先级档位提上来，因此这类请求会被拒绝。不同 Key 分别绑定的上游配置，应设置相同的 priority。
- **只有一个调度器插件生效。** CPA 中只有一个调度器插件生效，即已启用且优先级最高的那个。如果启用了其他调度器插件，请明确配置各插件的优先级。
- **CPA Home 模式和其他调度器。** CPA 节点连接到 CLIProxyAPIHome 后，凭证调度由 Home 负责，本插件的调度器会被绕过；启用了其他调度器插件时也是如此。after-auth 检查仍会拦截不允许的上游配置，但无法改派请求。在这种部署下，只要 Key 存在同类的精确拒绝规则，对 Gemini、Gemini Interactions、Claude、Codex 或 xAI API Key 上游配置的请求都会被拒绝，因为没有调度器就无法核验旧格式的拒绝规则。OAuth 和 OpenAI 兼容类上游配置不受影响。在这种部署下，优先使用白名单，而不是精确拒绝规则。
- **拒绝规则与 ID 变化。** 规则按上游配置 ID 匹配，而修改 API Key、base URL、proxy URL、prefix、headers 或供应商名称都会改变 ID。失效的允许规则匹配不到任何上游配置，结果是拒绝请求；失效的拒绝规则则会悄悄失去作用，不再拦截新的 ID。需要隔离时，优先使用白名单。

## 配置

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-provider-access:
      enabled: true
      priority: 100
      version: 2
      policies: []
```

设置页地址：

```text
/v0/resource/plugins/key-provider-access/settings
```

设置页复用同源的 CPAMC 或 CPAMP 管理会话（支持 `enc::v1` 和 `enc::v2` 存储格式），读取 CPA 的下游 Key 来计算 caller scope，并通过 CPA 只读的 auth 和配置管理接口构建上游配置目录。供应商密钥只在内存中临时用于复现 CPA 的稳定 auth ID，不会写入插件状态、DOM、浏览器存储或 URL。

设置页只显示每个下游 Key 的首尾部分，中间部分始终隐藏。完整的下游 Key 不会被持久化。

允许和拒绝的选项发生重叠时会显示为灰色，但仍可点击：选中其中一项，会从另一侧移除冲突的规则。在 `*` 生效时点击单个上游配置，会把通配符展开为当前目录中的具体上游配置，并排除被点击的那一项。

首次使用时，设置页会创建 `plugins/key-provider-access/config.toml`，并且只修改本插件的 `policy_file` 设置。策略更新使用修订版本 ETag 和原子文件替换。

## 策略格式

```toml
version = 2

[[policies]]
caller_scope = "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
allow_profiles = ["codex:apikey:abc123def456", "oauth-profile-id"]
deny_profiles = ["*-retired"]
```

请通过设置页计算 caller scope 并选择当前的上游配置 ID。不要在策略文件中写入原始下游 Key、OAuth 凭证材料或供应商 API Key。

## 构建与测试

```bash
make check
make build
```

Linux amd64 的构建产物是 `dist/key-provider-access.so`。将其安装为 `plugins/linux/amd64/key-provider-access-v0.1.0.so`（或不带版本后缀的文件名），并启用对应的 `key-provider-access` 配置项。

## 管理接口

- `GET /v0/management/plugins/key-provider-access/status`
- `GET/PUT /v0/management/plugins/key-provider-access/policies`
- `POST /v0/management/plugins/key-provider-access/reload`
- `POST /v0/management/plugins/key-provider-access/initialize-storage`

所有接口都使用 CPA 管理认证。状态输出不会包含 caller scope 或凭证。
