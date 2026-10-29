# Website-Fingerprinting-Library (WFlib)

<p align="center">
<img src=".\figures\wflib.jpg" height = "180" alt="" align=center />
<br><br>
</p>

**[News]** Our paper on enhancing website fingerprinting adaptability to traffic drift has been accepted by NDSS 2026. Code: https://github.com/Xinhao-Deng/Adaptive-WF-Attack


WFlib is a Pytorch-based open-source library for website fingerprinting attacks, intended for research purposes only.

Website fingerprinting is a type of network attack in which an adversary attempts to deduce which website a user is visiting based on encrypted traffic patterns, even without directly seeing the content of the traffic.

We provide a neat code base to evaluate 11 advanced DL-based WF attacks on multiple datasets. This library is derived from our ACM CCS 2024 paper. If you find this repo useful, please cite our paper.

```bibtex
@inproceedings{deng2024wflib,
  title={Robust and Reliable Early-Stage Website Fingerprinting Attacks via Spatial-Temporal Distribution Analysis},
  author={Deng, Xinhao and Li, Qi and Xu, Ke},
  booktitle={Proceedings of the 2024 ACM SIGSAC Conference on Computer and Communications Security},
  year={2024}
}
```

Contributions via pull requests are welcome and appreciated.

## WFlib Overview

The code library includes 11 DL-based website fingerprinting attacks.

| Attacks | Conference  | Paper | Code |
|----------|----------|----------|----------|
| AWF | NDSS 2018 | [Automated Website Fingerprinting through Deep Learning](https://arxiv.org/pdf/1708.06376) | [DLWF](https://github.com/DistriNet/DLWF) |
| DF | CCS 2018 | [Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning](https://dl.acm.org/doi/pdf/10.1145/3243734.3243768) | [df](https://github.com/deep-fingerprinting/df) |
| Tik-Tok | PETS 2019 | [Tik-Tok: The Utility of Packet Timing in Website Fingerprinting Attacks](https://petsymposium.org/popets/2020/popets-2020-0043.pdf) | [Tik_Tok](https://github.com/msrocean/Tik_Tok) |
| Var-CNN | PETS 2019 | [Var-CNN: A Data-Efficient Website Fingerprinting Attack Based on Deep Learning](https://arxiv.org/pdf/1802.10215) | [Var-CNN](https://github.com/sanjit-bhat/Var-CNN) |
| TF | CCS 2019 | [Triplet Fingerprinting: More Practical and Portable Website Fingerprinting with N-shot Learning](https://dl.acm.org/doi/pdf/10.1145/3319535.3354217) | [tf](https://github.com/triplet-fingerprinting/tf) |
| BAPM | ACSAC 2021 | [BAPM: Block Attention Profiling Model for Multi-tab Website Fingerprinting Attacks on Tor](https://dl.acm.org/doi/pdf/10.1145/3485832.3485891) | None |
| ARES | S&P 2023 | [Robust Multi-tab Website Fingerprinting Attacks in the Wild](https://arxiv.org/pdf/2501.12622) | [Multitab-WF-Datasets](https://github.com/Xinhao-Deng/Multitab-WF-Datasets) |
| RF | Security 2023 | [Subverting Website Fingerprinting Defenses with Robust Traffic Representation](https://www.usenix.org/system/files/sec23fall-prepub-621_shen-meng.pdf) | [RF](https://github.com/robust-fingerprinting/RF) |
| NetCLR | CCS 2023 | [Realistic Website Fingerprinting By Augmenting Network Trace](https://arxiv.org/pdf/2309.10147) | [Realistic-Website-Fingerprinting-By-Augmenting-Network-Traces](https://github.com/SPIN-UMass/Realistic-Website-Fingerprinting-By-Augmenting-Network-Traces) |
| TMWF | CCS 2023 | [Transformer-based Model for Multi-tab Website Fingerprinting Attack](https://dl.acm.org/doi/abs/10.1145/3576915.3623107) | [TMWF](https://github.com/jzx-bupt/TMWF) |
| Holmes | CCS 2024 | [Robust and Reliable Early-Stage Website Fingerprinting Attacks via Spatial-Temporal Distribution Analysis](https://arxiv.org/pdf/2407.00918) | [WFlib](https://github.com/Xinhao-Deng/Website-Fingerprinting-Library)|


We implemented all attacks using the same framework (Pytorch) and a consistent coding style, enabling researchers to evaluate and compare existing attacks easily.

## Usage

### Install 

```sh
git clone git@github.com:Xinhao-Deng/Website-Fingerprinting-Library.git
pip install --user .
```

**Note**

- Python 3.8 is required.

### Datasets

```sh
mkdir datasets
```

- Download datasets ([link](https://zenodo.org/records/13732130)) and place it in the folder `./datasets`

| Datasets | # of monitored websites | # of instances | Intro |
| --- | --- | --- | --- |
| CW.npz | 95 | 105730 | Closed-world dataset. [Details](https://dl.acm.org/doi/pdf/10.1145/3243734.3243768)|
| OW.npz |  95 | 146446 | Open-world dataset. [Details](https://dl.acm.org/doi/pdf/10.1145/3243734.3243768) |
| WTF-PAD.npz | 95 | 105730 | Dataset with WTF-PAD defense. [Details](https://arxiv.org/pdf/1512.00524) |
| Front.npz |  95 | 95000 | Dataset with Front defense. [Details](https://www.usenix.org/system/files/sec20-gong.pdf) |
| Walkie-Talkie.npz |  100 | 90000 | Dataset with Walkie-Talkie defense. [Details](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-wang-tao.pdf) |
| TrafficSliver.npz |  95 | 95000 | Dataset with TrafficSliver defense. [Details](https://sebastianreuter.info/publications/pdf/ccs-trafficsliver.pdf) |
| NCDrift_sup.npz |  93 | 21430 | Network condition drift dataset, including superior traces. [Details](https://arxiv.org/pdf/2309.10147) |
| NCDrift_inf.npz |  93 | 6882 | Network condition drift dataset, including inferior traces. [Details](https://arxiv.org/pdf/2309.10147) |
| Closed_2tab.npz |  100 | 58000 | 2-tab dataset in the closed-world scenario. [Details](http://www.thucsnet.com/wp-content/papers/xinhao_sp2023.pdf) |
| Closed_3tab.npz |  100 | 58000 | 3-tab dataset in the closed-world scenario. [Details](http://www.thucsnet.com/wp-content/papers/xinhao_sp2023.pdf)  |
| Closed_4tab.npz |  100 | 58000 | 4-tab dataset in the closed-world scenario. [Details](http://www.thucsnet.com/wp-content/papers/xinhao_sp2023.pdf)  |
| Closed_5tab.npz |  100 | 58000 | 5-tab dataset in the closed-world scenario. [Details](http://www.thucsnet.com/wp-content/papers/xinhao_sp2023.pdf)  |
| Open_2tab.npz |  100 | 64000 | 2-tab dataset in the open-world scenario. [Details](http://www.thucsnet.com/wp-content/papers/xinhao_sp2023.pdf)  |
| Open_3tab.npz |  100 | 64000 | 3-tab dataset in the open-world scenario. [Details](http://www.thucsnet.com/wp-content/papers/xinhao_sp2023.pdf)  |
| Open_4tab.npz |  100 | 64000 | 4-tab dataset in the open-world scenario. [Details](http://www.thucsnet.com/wp-content/papers/xinhao_sp2023.pdf) |
| Open_5tab.npz |  100 | 64000 | 5-tab dataset in the open-world scenario. [Details](http://www.thucsnet.com/wp-content/papers/xinhao_sp2023.pdf) |


- The extracted dataset is in npz format and contains two values: X and y. X represents the cell sequence, with values being the direction (e.g., 1 or -1) multiplied by the timestamp. y corresponds to the labels. Note that the input of some datasets consists only of direction sequences.

- Divide the dataset into training, validation, and test sets.

```sh
# For single-tab datasets
python exp/dataset_process/dataset_split.py --dataset CW
# For multi-tab datasets
python exp/dataset_process/dataset_split.py --dataset Closed_2tab --use_stratify False
```

### Extracting verified QUIC captures

`pcap_pipeline.py` accepts the same part directories as the QUIC classifier pipeline:

```text
<part>/data/verified/<defense>/<domain>/<session>/
    receipt.json                 # optional
    pcaps/traffic.pcap           # or traffic.pcapng
```

Install Wireshark with TShark (4.2+ recommended) and the Python dependencies in
`requirements.txt`. Run from the repository root:

```sh
python pcap_pipeline.py /path/to/part1 /path/to/part2 --out-dir datasets --seq-len 10000
# Optionally also extract all aggregated model features:
python pcap_pipeline.py /path/to/part1 --out-dir datasets --features TAM TAF MTAF
```

The pipeline writes one sample per session capture and one dataset per defense,
for example `datasets/Front.npz` and `datasets/Front.labels.json`. Raw `X` has shape
`(N, seq_len)` with signed relative timestamps in seconds: outgoing is positive,
incoming is negative, and padding is zero. Packets at relative time zero use
`1e-9` seconds so WFlib does not mistake them for padding. Each UDP datagram counts
once, even when it contains multiple QUIC packets; packet lengths and decrypted
QUIC frame contents are not model features in this library.

Raw datasets work with `load_data` features `DIR`, `DT`, and `DT2`. Optional files
`Front_tam.npz`, `Front_taf.npz`, and `Front_mtaf.npz` contain the existing WFlib
representations with shapes `(N, 2, 1800)`, `(N, 3, 2, 2000)`, and `(N, 8, 8000)`.
They use the same retained packet window as the raw dataset. Choose `--seq-len`
to match your experiment (existing feature-generation scripts default to 5000).
These are single-domain labels; multi-tab ground truth cannot be inferred from
this folder structure.

Receipts validate folder labels and select the exact UDP five-tuple. Without a
receipt, client direction is inferred from a QUIC ClientHello; use
`--client-address IP` when it is unavailable. Only canonical traffic captures
are included. Direct PCAP inputs require `--domain DOMAIN`. Other options include
`--tshark PATH`, repeatable `--port PORT` to force QUIC decoding, and
`--skip-invalid` to report and omit invalid captures. Duplicate capture contents
are rejected. Invalid receipts always fail discovery.

Archives also store `groups` and `captures` as string arrays, readable without
pickle. Receipt groups match study/domain/slot across defenses; without receipts,
groups match domain/session names. Keep each group entirely within one training,
validation, or test partition, including comparisons across defenses. The existing
`dataset_split.py` uses sample-level splitting and does not preserve these groups.
Labels are contiguous within each defense; consult its label map when comparing
datasets. Outputs are complete datasets, not pre-split training files. Split the
raw data by group before using the existing `gen_tam.py`, `gen_taf.py`, or
`gen_mtaf.py` scripts to generate the training file names used by model scripts.

### Training \& Evaluation

We provide all experiment scripts for WF attacks in the folder `./scripts/`. For example, you can reproduce the DF attack on the CW dataset by executing the following command.

```sh
bash scripts/DF.sh
```

The `./scripts/DF.sh` file contains the commands for model training and evaluation.

```sh
dataset=CW

python -u exp/train.py \
  --dataset ${dataset} \
  --model DF \
  --device cuda:1 \
  --feature DIR \
  --seq_len 5000 \
  --train_epochs 30 \
  --batch_size 128 \
  --learning_rate 2e-3 \
  --optimizer Adamax \
  --eval_metrics Accuracy Precision Recall F1-score \
  --save_metric F1-score \
  --save_name max_f1

python -u exp/test.py \
  --dataset ${dataset} \
  --model DF \
  --device cuda:1 \
  --feature DIR \
  --seq_len 5000 \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1
```

The meanings of all parameters can be found in the `exp/train.py` and `exp/test.py` files. WFlib supports modifying parameters to easily implement different attacks. Moreover, you can use WFlib to implement combinations of different attacks or perform ablation analysis.

## Contact
If you have any questions or suggestions, feel free to contact:

- [Xinhao Deng](https://xinhao-deng.github.io/) (xinhaodeng.thu@gmail.com)
- Yixiang Zhang (zhangyix24@mails.tsinghua.edu.cn)

## Acknowledgements

We would like to thank all the authors of the referenced papers.
