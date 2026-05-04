# Test-only Perturbation Smoke

生成日期：2026-05-04

## 1. 设置

- split：`0`
- train sample：`20000`
- test sample：`20000`
- 模型：RandomForest(n_estimators=80, max_depth=14)
- groups：`ip_ttl_protocol,tcp_flags_window,tcp_options,current_mask_top_shortcut_columns,random_same_size`
- perturb modes：`zero,permute`
- 未运行 AutoGluon、Pcap-Encoder、Denoiser、QA 或 accelerate。

## 2. 结果

| group | mode | columns | raw macro F1 | perturbed macro F1 | drop |
|---|---|---|---:|---:|---:|
| `current_mask_top_shortcut_columns` | `zero` | `4,16,17,20,21,22,23,24,25` | 0.9998 | 0.2867 | 0.7131 |
| `tcp_options` | `zero` | `20,21,22,23,24,25` | 0.9998 | 0.2989 | 0.7010 |
| `current_mask_top_shortcut_columns` | `permute` | `4,16,17,20,21,22,23,24,25` | 0.9998 | 0.4983 | 0.5015 |
| `tcp_options` | `permute` | `20,21,22,23,24,25` | 0.9998 | 0.7144 | 0.2854 |
| `ip_ttl_protocol` | `permute` | `4` | 0.9998 | 0.9927 | 0.0071 |
| `ip_ttl_protocol` | `zero` | `4` | 0.9998 | 0.9930 | 0.0068 |
| `random_same_size` | `zero` | `1,3,5,10,12,15,18,29,31` | 0.9998 | 0.9932 | 0.0067 |
| `random_same_size` | `permute` | `1,3,5,10,12,15,18,29,31` | 0.9998 | 0.9946 | 0.0052 |
| `tcp_flags_window` | `permute` | `16,17` | 0.9998 | 0.9970 | 0.0029 |
| `tcp_flags_window` | `zero` | `16,17` | 0.9998 | 0.9999 | 0.0000 |

## 3. 解释

这个 smoke 不重新训练 masked 模型，而是在 raw-trained lightweight RF 上只扰动 test。drop 越大，说明 raw 模型推理时越依赖该 group；random_same_size 用来检查这种敏感性是否只是“随便遮 9 列都会掉”。
本次 smoke 中最敏感的是 `current_mask_top_shortcut_columns` / `zero`，macro F1 drop=0.7131。
