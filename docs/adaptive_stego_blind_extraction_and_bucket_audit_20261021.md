# 自适应图像隐写盲提取机制与类桶约束（Class Bucket）技术审计报告

> **编制时间**：2026-10-21 20:10:00  
> **审计对象**：`strhide` 自适应隐写信道自同步机制、JPEG 频域 `|c| & !1` 类桶、空间域 `0xF8` 类桶  
> **关联设计记录**：`docs/stego_keyed_parameters_plan_20261020.md`、`docs/stego_plan_independent_review_20261021_144914.md`  
> **对比开源项目**：`temp/github/hstego`、`temp/github/pySTC`、`temp/github/phasmcore`

---

## 摘要

在 `strhide` 的 JPEG 与空间域自适应隐写实现中，存在一个核心约束——**二元类桶约束（Class Bucket Constraint）**：
* JPEG 频域：限制改动必须保持 `|c| & !1` 不变，导致正偶数只能 $+1$，正奇数只能 $-1$（[`rust/src/stego/coding.rs:323-338`](file:///c:/Home/Projects/strhide/rust/src/stego/coding.rs#L323-L338)）；
* 空间域：限制像素值必须保持在 8 值类 `val & 0xF8` 内，导致类底 `val % 8 == 0` 只能 $+1$，类顶 `val % 8 == 7` 只能 $-1$。

本报告对这一约束的**必要性、设计历史成因、学术界横向对比以及引发的安全性代价**进行了深入审计。核心审计结论如下：

1. **类桶约束不是实现盲提取的唯一途径，更不是学术界标准做法**：对比 `hstego`、`pySTC`、`phasmcore` 可知，主流开源自适应隐写工具均通过“密码全局伪随机置换（PRNG Shuffle）+ STC 软避障”实现 100% 盲提取，天然支持对称的三元嵌入（$\{-1, 0, +1\}$），无需任何类桶约束。
2. **类桶约束是局部代价排序架构下的特有补丁**：`strhide` 在早期演进中引入了“正文按代价排序截选前 $N$ 槽”的设计。为了让提取端在本地能够重现这一完全相同的代价排序，被迫要求代价图在嵌入前后绝对不变，进而衍生出了掩码归一化（Canonical Space）与类桶锁死。
3. **类桶体系带来了明确的隐写分析缺陷**：类边界的单向门移动破坏了自然直方图分布，在特定差分直方图上产生了高达 **$9\sigma$ 异常的残差赤字指纹**，同时将三元改动降维为二元，剥夺了维纳极化等高级频域补偿算法发挥作用的物理空间。

---

## 一、自适应隐写盲提取的“信道同步死锁”

在数字隐写系统中，“盲提取（Blind Extraction）”意味着：**接收方手中只有带有秘密信息的 Stego 图片，没有任何原始 Cover 图片，也没有任何带外的信道坐标索引文件。**

而在内容自适应隐写（如 UERD、HILL）中，嵌入必须优先挑复杂的纹理区域：
1. 嵌入端读取原始系数 $c$，计算代价图 $\rho(c)$，排序筛选出代价最低的前 $K$ 个槽位；
2. 嵌入端修改了部分系数：$c \rightarrow c'$；
3. 接收端收到图片，只能读取被修改过的系数 $c'$，并重新计算代价图 $\rho(c')$；
4. **死锁矛盾**：如果修改系数改变了局部能量，导致 $\rho(c') \neq \rho(c)$，接收端排出的槽位顺序就会发生错位（Desynchronization）。一旦发生一位错位，整个 STC 或汉明纠错矩阵就会全线雪崩，隐写数据彻底损坏。

---

## 二、`strhide` 现有类桶体系的设计溯源

查阅项目文档库中的真实设计演进记录可知，类桶约束并非项目初始的核心架构，而是在评审解决“失真控制”时产生的伴生方案。

在 [`docs/stego_keyed_parameters_plan_20261020.md`](file:///c:/Home/Projects/strhide/docs/stego_keyed_parameters_plan_20261020.md#L518-L520) §13.2 发现与处置表中记录：

> *“4. 正文槽位取‘全量置换后的前 N’，等价随机子集，丢掉 HILL 最小失真前提（实测改动像素中位代价是‘最便宜 N 槽’的 4.3 倍）| **改为：头部仍取密钥化随机 256 槽，正文在剩余候选里按代价取前 N 再洗牌；新增 `test_stego_body_slots_follow_cost_order` 守住**”*

这一决策导致了后续链条的连锁反应：
1. **决定在正文按代价排序截选前 N 个槽位**；
2. 为了提取端能找出“哪前 N 个槽位”，**提取端必须在本地完整重算 UERD/HILL 能量图并重新排序**；
3. 为了确保提取端算出的能量与嵌入前绝对一致，引入了掩码归一化：
   - 频域 UERD：`coeff_energy = (coeff.abs() & !1) as f64`（[`rust/src/stego/jpeg/cost/uerd.rs:83-87`](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/cost/uerd.rs#L83-L87)）；
   - 空域 HILL：`val & 0xF8`（[`rust/src/stego/spatial/cost/hill.rs`](file:///c:/Home/Projects/strhide/rust/src/stego/spatial/cost/hill.rs)）；
4. 为了确保系数在修改后不跨出所属的类桶（跨出即改变能量），修改方向被物理锁死：
   - 正偶数只能 $+1$（变成正奇数，`|c| & !1` 不变）；
   - 正奇数只能 $-1$（变成正偶数，`|c| & !1` 不变）；
   - **绝对禁止反向跨桶移动**。

---

## 三、横向对比：主流开源自适应隐写是如何实现盲提取的？

为核实“别人是否也用类桶”，深入查阅了本地 `temp/github` 的成熟开源项目：

```
               ┌────────────────────────────────────────────────────────┐
               │           主流自适应隐写盲提取架构分类                    │
               └───────────────────────────┬────────────────────────────┘
                                           │
                 ┌─────────────────────────┴─────────────────────────┐
                 ▼                                                   ▼
     【模式 A：全局置换 + STC 软避障】                    【模式 B：局部代价排序 + 类桶锁定】
        (HStego / pySTC / phasmcore)                              (strhide 当前实现)
  - 提取端不计算任何图像代价                           - 提取端必须在本地重算代价图并排序
  - 信道位置完全由密码 PRNG Shuffle 决定              - 信道位置由代价排序的前 N 个槽位决定
  - 三元自由移动 ({-1, 0, +1})                        - 二元锁死 (偶数只能+1，奇数只能-1)
  - 维纳代价极化天然有效                               - 维纳代价极化产生负向扰动
```

### 1. `temp/github/hstego`（Daniel Lerch 的 HStego）
* **提取实现**（[`hstegolib.py:606-609`](file:///c:/Home/Projects/strhide/temp/github/hstego/hstegolib.py#L606-L609)）：
  ```python
  indices = list(range(len(stego_array)))
  random.shuffle(indices)
  stego_array = stego_array[indices]
  return self.unhide_stc(stego_array[reserved_prefix:], byte_len * 8)
  ```
* **机理**：提取端根本不调用 `cost_fn`，直接使用密码洗牌后的数组解校验子。代价图仅在嵌入端传给 STC，STC 的 Viterbi 算法自动跳过高代价区域。
* **特性**：无需类桶，每个系数自由 $+1$ 或 $-1$。

### 2. `temp/github/pySTC`（Fridrich 实验室官方 STC 封装）
* **提取实现**（[`pystc/pystc.py:137-154`](file:///c:/Home/Projects/strhide/temp/github/pySTC/pystc/pystc.py#L137-L154)）：
  ```python
  def unhide(stego_matrix, password_seed):
      indices = list(range(len(stego_array)))
      random.shuffle(indices)
      ...
      data = _unhide_stc(stego_array[64:], data_len)
      return data
  ```
* **特性**：入参仅为矩阵与密码种子，零代价计算，100% 盲提取。

### 3. `temp/github/phasmcore`（Rust 原生视频/图像自适应隐写）
* **提取实现**（[`src/stego/stc/extract.rs`](file:///c:/Home/Projects/strhide/temp/github/phasmcore/src/stego/stc/extract.rs)）：
  通过 ChaCha20 PRNG 流驱动的全局置换定位信道，提取端前缀只读固定 Frame Overhead，零特征反算。

---

## 四、类桶体系带来的隐写分析缺陷与代价

在独立评审报告 [`docs/stego_plan_independent_review_20261021_144914.md`](file:///c:/Home/Projects/strhide/docs/stego_plan_independent_review_20261021_144914.md#L174-L260) §4 中，已对类桶体系的抗检缺陷进行了定量证实：

1. **单向门导致严重的类边界统计赤字（Residue Deficit）**：
   * 空间域中，`val % 8 == 0` 只能 $+1$，`val % 8 == 7` 只能 $-1$；
   * 嵌入后，模 8 余数为 0 和 7 的直方图频数发生不对称萎缩，实测产生了高达 **$9\sigma$ 异常的统计信号**；
   * 这种人造结构使得现代隐写分析器即使不用深度学习，仅通过特定的余数残差检验就能直接断定隐写的存在。
2. **编码效率降低**：
   * 二元覆盖码（Binary Move）的平均比特改动率为 $\sim 0.25$；
   * 标准三元 STC（Ternary Move）的平均比特改动率为 $\sim 0.20$；
   * 二元类桶比三元嵌入多改动了约 **15% ~ 20%** 的载体系数。
3. **彻底瘫痪连续侧信息估计（维纳极化）**：
   * 维纳极化的核心是“二选一”：在 $+1$ 和 $-1$ 中挑选顺应连续波形截断误差的那个方向；
   * 类桶将方向物理锁死后，极化无法执行方向优化，反而打折了高能系数的代价，导致频域 DCTR 8000 维特征漂移扩大。

---

## 五、架构技术审计结论

1. **二元类桶约束是局部代价排序架构下的特异性产物**，并非盲提取在数学上的绝对必需；
2. **继续保留类桶约束的代价是沉重的**：它锁死了三元自由度、瘫痪了维纳极化、引入了类边界统计赤字；
3. **唯一的解耦途径**：抛弃“在提取端重算代价图以截选前 N 槽”的私有架构，全面迁移至学术界通用的“全图非零系数置换 + STC 自动寻路”标准架构（模式 A）。
