import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

class ConvBn(nn.Module):
    def __init__(self, in_c, out_c, k=3, s=1, p=1):
        super().__init__()
        self.conv = nn.Conv2d(in_c, out_c, kernel_size=k, stride=s, padding=p, bias=True)
        self.bn = nn.BatchNorm2d(out_c, eps=0.001, momentum=0.01)

    def forward(self, x):
        return self.bn(self.conv(x))

class Type1(nn.Module):
    def __init__(self, in_c, out_c, k=3, s=1, p=1):
        super().__init__()
        self.convbn = ConvBn(in_c, out_c, k=k, s=s, p=p)
        self.relu = nn.ReLU(inplace=True)

    def forward(self, x):
        return self.relu(self.convbn(x))

class Type2(nn.Module):
    def __init__(self, c=16):
        super().__init__()
        self.t1 = Type1(c, c)
        self.convbn = ConvBn(c, c)

    def forward(self, x):
        return x + self.convbn(self.t1(x))

class Type3(nn.Module):
    def __init__(self, in_c, out_c):
        super().__init__()
        # Shortcut branch (1x1 stride 2)
        self.shortcut_conv = nn.Conv2d(in_c, out_c, kernel_size=1, stride=2, padding=0, bias=True)
        self.shortcut_bn = nn.BatchNorm2d(out_c, eps=0.001, momentum=0.01)

        # Main branch: Type1 -> ConvBn -> AvgPool
        self.t1 = Type1(in_c, out_c)
        self.convbn = ConvBn(out_c, out_c)
        self.pool = nn.AvgPool2d(kernel_size=3, stride=2, padding=1)

    def forward(self, x):
        shortcut = self.shortcut_bn(self.shortcut_conv(x))
        main = self.pool(self.convbn(self.t1(x)))
        return shortcut + main

class Type4(nn.Module):
    def __init__(self, in_c=256, out_c=512):
        super().__init__()
        self.t1 = Type1(in_c, out_c)
        self.convbn = ConvBn(out_c, out_c)
        self.gap = nn.AdaptiveAvgPool2d((1, 1))

    def forward(self, x):
        return self.gap(self.convbn(self.t1(x)))

class SRNet(nn.Module):
    def __init__(self, in_channels=3):
        super().__init__()
        # Layer 1 & 2
        self.layer1 = Type1(in_channels, 64)
        self.layer2 = Type1(64, 16)

        # 5 Type2 blocks (layers 3 to 7)
        self.t2_blocks = nn.ModuleList([Type2(16) for _ in range(5)])

        # 4 Type3 blocks (layers 8 to 11)
        self.t3_blocks = nn.ModuleList([
            Type3(16, 16),
            Type3(16, 64),
            Type3(64, 128),
            Type3(128, 256),
        ])

        # Type4 block (layer 12)
        self.t4 = Type4(256, 512)

        # Classifier
        self.dense = nn.Linear(512, 2, bias=False)

    def forward(self, x):
        x = self.layer1(x)
        x = self.layer2(x)
        for blk in self.t2_blocks:
            x = blk(x)
        for blk in self.t3_blocks:
            x = blk(x)
        x = self.t4(x)
        x = x.view(x.size(0), -1)
        logits = self.dense(x)
        probs = F.softmax(logits, dim=-1)
        return probs

def load_keras_weights_to_pytorch(pt_model, npz_path):
    data = np.load(npz_path)

    def set_conv(conv_layer, name):
        w = data[f"{name}__0"]  # (H, W, Cin, Cout)
        b = data[f"{name}__1"]  # (Cout,)
        conv_layer.weight.data = torch.from_numpy(w).permute(3, 2, 0, 1)
        conv_layer.bias.data = torch.from_numpy(b)

    def set_bn(bn_layer, name):
        gamma = data[f"{name}__0"]
        beta = data[f"{name}__1"]
        mean = data[f"{name}__2"]
        var = data[f"{name}__3"]
        bn_layer.weight.data = torch.from_numpy(gamma)
        bn_layer.bias.data = torch.from_numpy(beta)
        bn_layer.running_mean.data = torch.from_numpy(mean)
        bn_layer.running_var.data = torch.from_numpy(var)

    # Layer 1
    set_conv(pt_model.layer1.convbn.conv, "conv2d")
    set_bn(pt_model.layer1.convbn.bn, "batch_normalization")

    # Layer 2
    set_conv(pt_model.layer2.convbn.conv, "conv2d_1")
    set_bn(pt_model.layer2.convbn.bn, "batch_normalization_1")

    # Type 2 blocks (5 blocks)
    # block 0: conv2d_2, conv2d_3
    # block 1: conv2d_4, conv2d_5
    # block 2: conv2d_6, conv2d_7
    # block 3: conv2d_8, conv2d_9
    # block 4: conv2d_10, conv2d_11
    for i, blk in enumerate(pt_model.t2_blocks):
        c1_idx = 2 + i * 2
        c2_idx = 3 + i * 2
        set_conv(blk.t1.convbn.conv, f"conv2d_{c1_idx}")
        set_bn(blk.t1.convbn.bn, f"batch_normalization_{c1_idx}")
        set_conv(blk.convbn.conv, f"conv2d_{c2_idx}")
        set_bn(blk.convbn.bn, f"batch_normalization_{c2_idx}")

    # Type 3 blocks:
    # Block 0 (16->16): main conv2d_13, conv2d_14; shortcut conv2d_12
    set_conv(pt_model.t3_blocks[0].t1.convbn.conv, "conv2d_13")
    set_bn(pt_model.t3_blocks[0].t1.convbn.bn, "batch_normalization_13")
    set_conv(pt_model.t3_blocks[0].convbn.conv, "conv2d_14")
    set_bn(pt_model.t3_blocks[0].convbn.bn, "batch_normalization_14")
    set_conv(pt_model.t3_blocks[0].shortcut_conv, "conv2d_12")
    set_bn(pt_model.t3_blocks[0].shortcut_bn, "batch_normalization_12")

    # Block 1 (16->64): main conv2d_16, conv2d_17; shortcut conv2d_15
    set_conv(pt_model.t3_blocks[1].t1.convbn.conv, "conv2d_16")
    set_bn(pt_model.t3_blocks[1].t1.convbn.bn, "batch_normalization_16")
    set_conv(pt_model.t3_blocks[1].convbn.conv, "conv2d_17")
    set_bn(pt_model.t3_blocks[1].convbn.bn, "batch_normalization_17")
    set_conv(pt_model.t3_blocks[1].shortcut_conv, "conv2d_15")
    set_bn(pt_model.t3_blocks[1].shortcut_bn, "batch_normalization_15")

    # Block 2 (64->128): main conv2d_19, conv2d_20; shortcut conv2d_18
    set_conv(pt_model.t3_blocks[2].t1.convbn.conv, "conv2d_19")
    set_bn(pt_model.t3_blocks[2].t1.convbn.bn, "batch_normalization_19")
    set_conv(pt_model.t3_blocks[2].convbn.conv, "conv2d_20")
    set_bn(pt_model.t3_blocks[2].convbn.bn, "batch_normalization_20")
    set_conv(pt_model.t3_blocks[2].shortcut_conv, "conv2d_18")
    set_bn(pt_model.t3_blocks[2].shortcut_bn, "batch_normalization_18")

    # Block 3 (128->256): main conv2d_22, conv2d_23; shortcut conv2d_21
    set_conv(pt_model.t3_blocks[3].t1.convbn.conv, "conv2d_22")
    set_bn(pt_model.t3_blocks[3].t1.convbn.bn, "batch_normalization_22")
    set_conv(pt_model.t3_blocks[3].convbn.conv, "conv2d_23")
    set_bn(pt_model.t3_blocks[3].convbn.bn, "batch_normalization_23")
    set_conv(pt_model.t3_blocks[3].shortcut_conv, "conv2d_21")
    set_bn(pt_model.t3_blocks[3].shortcut_bn, "batch_normalization_21")

    # Type 4 block (256->512): conv2d_24, conv2d_25
    set_conv(pt_model.t4.t1.convbn.conv, "conv2d_24")
    set_bn(pt_model.t4.t1.convbn.bn, "batch_normalization_24")
    set_conv(pt_model.t4.convbn.conv, "conv2d_25")
    set_bn(pt_model.t4.convbn.bn, "batch_normalization_25")

    # Dense
    dense_w = data["dense__0"]  # (512, 2)
    pt_model.dense.weight.data = torch.from_numpy(dense_w).T

    return pt_model
