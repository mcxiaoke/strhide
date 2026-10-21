# StegoEval - 多层次图像隐写术综合检测与评估套件

专为 Windows 环境打造的自用、轻量、多维度数字图像隐写分析与量化评分套件。无需复杂的 Linux 依赖，零编译障碍，秒级出分。

---

## 一、架构体系（五大分析层级）

| 分析层级 | 核心检测算法 / 指标 | 针对的隐写手段 |
| :--- | :--- | :--- |
| **Tier 1: 容器与物理结构层** | 文件尾部追加数据检测 (Trailing Bytes Carving)、PNG 非标私有 Chunk 分析、JPEG 注释 (COM) 段、文件全局香农熵 | 文件尾部拼接隐写、非标 Chunk 注入、EXIF/COM 隐藏数据 |
| **Tier 2: 空域 LSB 经典统计层** | **RS 分析** (Regular-Singular Analysis, Fridrich)<br>**SPA 分析** (Sample Pairs Analysis, Dumitrescu)<br>**卡方检验** (Chi-Square Attack / PoVs, Westfeld)<br>**加权残差分析** (Weighted Stego, WS)<br>LSB 均值与奇偶直方图偏离度 | 空域 LSB 顺序替换、随机替换、$\pm 1$ 嵌入 (LSB Matching) |
| **Tier 3: 残差与空间高通动力学** | 一阶/二阶差分残差直方图方差与峰度 (Kurtosis)、$3\times 3$ Laplacian 滤波能量方差、零残差能量占比 | 自适应隐写 (S-UNIWARD, HILL, WOW) 引起的边缘与高频残差扰动 |
| **Tier 4: 频域与 DCT 统计分析** | 8x8 块 DCT 交流系数 (AC coefficients) 直方图正负对称性检验、零系数膨胀率 (Zero AC ratio) | JPEG 频域隐写 (J-Steg, OutGuess, F5 丢弃压缩痕迹) |
| **Tier 5: 深度学习模型外挂 (可选)** | 适配 `F:\ai\downloads\aletheia-models` 目录下的 Aletheia 预训练模型 (EfficientNet-B0 / SRNet) | 针对 Steghide, J-UNIWARD, F5, nsF5, HILL 等现代隐写的端到端分类 |

---

## 二、运行环境

脚本拥有专属的独立虚拟环境（已配置完备）：
- **Python 解释器**：`temp/stego_eval/.venv/Scripts/python.exe`
- **基础依赖**：NumPy, SciPy, OpenCV, Pillow, Rich, Click（已全部安装测试通过）

---

## 三、命令行使用指南

进入目录：
```cmd
cd C:\Home\Projects\strhide\temp\stego_eval
```

### 1. 单图多维度综合评估（控制台彩色仪表盘）
```bash
run.bat image.png
# 或直接调用 python：
.venv\Scripts\python.exe stego_eval.py image.png
```

### 2. 输出机器可读的 JSON 格式（供脚本 / 批测管道消费）
```bash
run.bat image.png --json
```

### 3. 目录批量全自动扫描（自动统计各风险级别数量并保存结果）
```bash
run.bat --dir C:/path/to/test_images/ -o batch_report.json
```

### 4. 启用深度学习模型（可选）
如果环境中安装了 TensorFlow，可开启 `--enable-dl` 联动 `F:\ai\downloads\aletheia-models`：
```bash
run.bat image.png --enable-dl
```

---

## 四、在 Python 脚本中直接调用 (API 方式)

你可以直接在自己的自动化脚本（例如评测 Rust 隐写输出抗检性）中作为 Python 模块直接调用：

```python
from pathlib import Path
import sys

# 引入 stego_eval 目录
sys.path.append(r"C:\Home\Projects\strhide\temp\stego_eval")
from stego_eval import evaluate_image

# 运行评估
report = evaluate_image(Path("suspect.png"))

score = report["summary"]["stego_score"]            # 0.0 ~ 100.0
verdict = report["summary"]["verdict"]              # CLEAN / LOW_RISK / SUSPICIOUS / HIGH_RISK
payload = report["summary"]["estimated_payload_pct"]# 估计载荷比例 (如 14.5%)

print(f"得分: {score}, 结论: {verdict}, 估计嵌入率: {payload}%")
```

---

## 五、综合评分规则 (Verdict)

- **`0.0 ~ 20.0 (CLEAN)`**：未检出明显隐写特征，各项统计指标落在正常自然图像范围内。
- **`20.0 ~ 45.0 (LOW_RISK)`**：低风险，图像边缘复杂或存在轻微压缩噪点，属于正常扰动。
- **`45.0 ~ 70.0 (SUSPICIOUS)`**：可疑，检测到中度统计偏离（如 LSB 奇偶拉平、差分峰度异常或 RS 估计有载荷）。
- **`70.0 ~ 100.0 (HIGH_RISK)`**：高危，检测到高确定性证据（如文件尾部拼接载荷、卡方 p-value 极高、高嵌入率）。
