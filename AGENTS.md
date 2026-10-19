# AGENTS.md

## 项目简介
`strhide` 是一个**智能、格式保持、无损的数据隐藏工具**：在普通文件中隐藏文本或文件，不改变格式、外观或功能，并能之后**还原**原始文件。

- `rust/`：Rust实现，编译为单一静态二进制，开发和维护中。
- `python/` 目录已冻结，不再改动，不要新增和修改任何代码。**

## 开发与测试流程

### 主要开发目标：`rust/`

```bash
cd rust
cargo build --release          # 编译，产物在 target/release/strhide
cargo test                     # 运行测试套件
cargo fmt && cargo clippy      # 提交前格式化并修复所有 lint
```

### 通用约定

- 改动代码前先核对影响面，不因修复旧问题引入新问题。
- 不自发 `commit`/`push`，除非明确要求。
