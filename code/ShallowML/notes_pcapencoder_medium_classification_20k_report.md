# Pcap-Encoder medium QA classification 20k report

日期：2026-05-03

状态：全部完成。

| split | raw accuracy | mask accuracy | accuracy drop | raw macro F1 | mask macro F1 | macro F1 drop | raw loss | mask loss |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| split0 | 0.8304 | 0.7927 | 3.78 pp | 0.8274 | 0.7858 | 4.16 pp | 0.4836 | 0.5220 |
| split1 | 0.8012 | 0.7739 | 2.74 pp | 0.7936 | 0.7634 | 3.03 pp | 0.5176 | 0.5367 |
| split2 | 0.7339 | 0.7357 | -0.18 pp | 0.7338 | 0.7356 | -0.18 pp | 0.5780 | 0.5759 |

平均：

- raw macro F1 = 0.7849
- mask macro F1 = 0.7616
- macro F1 平均下降 = 2.34 pp
- accuracy 平均下降 = 2.11 pp

说明：本阶段继续使用已训练好的 medium QA checkpoint，只做 downstream classification；没有重新训练 Denoiser 或 QA。
