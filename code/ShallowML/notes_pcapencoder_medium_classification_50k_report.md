# Pcap-Encoder medium QA classification 50k report

日期：2026-05-03

状态：全部完成。

| split | raw accuracy | mask accuracy | accuracy drop | raw macro F1 | mask macro F1 | macro F1 drop | raw loss | mask loss |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| split0 | 0.8224 | 0.7722 | 5.02 pp | 0.8196 | 0.7706 | 4.90 pp | 0.4902 | 0.5351 |
| split1 | 0.8330 | 0.8008 | 3.21 pp | 0.8291 | 0.7978 | 3.13 pp | 0.4802 | 0.5106 |
| split2 | 0.8350 | 0.7708 | 6.42 pp | 0.8315 | 0.7692 | 6.22 pp | 0.4785 | 0.5358 |

平均：

- raw macro F1 = 0.8267
- mask macro F1 = 0.7792
- macro F1 平均下降 = 4.75 pp
- accuracy 平均下降 = 4.89 pp

说明：本阶段继续使用已训练好的 medium QA checkpoint，只做 downstream classification；没有重新训练 Denoiser 或 QA。
