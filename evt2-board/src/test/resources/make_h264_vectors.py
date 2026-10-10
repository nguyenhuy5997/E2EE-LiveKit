"""Regenerates the H.264 test streams of H264QpParserTest (needs PyAV with libx264: pip install av numpy).

Constant QP with ipratio = pbratio = 1: every slice of every frame has the QP in the file name. stitchable=1 makes
x264 write pic_init_qp = 26 in the PPS, so slice_qp_delta is not zero and the test really checks that the slice
header is read to the right bit. Format: per frame, a 4-byte big-endian length and the Annex-B access unit.
"""
import fractions
import os
import struct

import av
import numpy as np

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "h264")


def encode(name, qp, x264_params, profile, n=12, w=160, h=128):
    cc = av.CodecContext.create("libx264", "w")
    cc.width, cc.height, cc.pix_fmt = w, h, "yuv420p"
    cc.time_base = fractions.Fraction(1, 30)
    cc.options = {"qp": str(qp), "profile": profile, "x264-params": "ipratio=1:pbratio=1:stitchable=1:" + x264_params}
    rng = np.random.default_rng(1)
    yy, xx = np.mgrid[0:h, 0:w]
    base = np.stack([(xx * 255 // w), (yy * 255 // h), ((xx + yy) % 64) * 4], -1).astype(np.uint8)
    base = (base // 2 + rng.integers(0, 128, (h, w, 3), dtype=np.uint8) // 4).astype(np.uint8)
    packets = []
    for i in range(n):
        frame = av.VideoFrame.from_ndarray(np.roll(base, i * 3, axis=1), format="rgb24").reformat(format="yuv420p")
        frame.pts = i
        packets += cc.encode(frame)
    packets += cc.encode(None)
    with open(os.path.join(OUT, name + ".bin"), "wb") as f:
        for p in packets:
            b = bytes(p)
            f.write(struct.pack(">I", len(b)) + b)
    print(name, len(packets), "frames")


if __name__ == "__main__":
    encode("baseline_qp30", 30, "keyint=6", "baseline")
    encode("baseline_qp22_slices", 22, "slices=3:keyint=6", "baseline")
    encode("high_qp35_b_weightp", 35, "bframes=2:b-pyramid=normal:weightp=2:ref=3:keyint=8", "high")
