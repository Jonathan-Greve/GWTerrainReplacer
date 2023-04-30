import numpy as np
from PIL import Image

from gw_texture_manager.dds_dxt1 import DXT1Color


def process_dxt3(data, xr, yr):
    coltable = np.empty((xr * yr // 16), dtype=DXT1Color)
    alphatable = np.empty((xr * yr // 16), dtype=np.int64)
    blocktable = np.empty((xr * yr // 16), dtype=np.uint32)

    d = np.array(data, dtype=np.uint32)

    for x in range(xr * yr // 16):
        alphatable[x] = np.frombuffer(d[x * 4:x * 4 + 2], dtype=np.int64)[0]
        coltable[x] = DXT1Color(d[x * 4 + 2], d[x * 4 + 3])
        blocktable[x] = d[x * 4 + 3]

    image = np.zeros((yr, xr, 4), dtype=np.uint8)

    p = 0
    for y in range(0, yr, 4):
        for x in range(0, xr, 4):
            ctbl = np.zeros((4, 4), dtype=np.uint8)
            ctbl[:, 3] = 255
            c = coltable[p]
            ctbl[0, :3] = c.r1, c.g1, c.b1
            ctbl[1, :3] = c.r2, c.g2, c.b2

            ctbl[2, :3] = (ctbl[0, :3] * 2 + ctbl[1, :3]) // 3
            ctbl[3, :3] = (ctbl[0, :3] + ctbl[1, :3] * 2) // 3

            t = blocktable[p]
            k = alphatable[p]

            for b in range(4):
                for a in range(4):
                    image[y + b, x + a] = ctbl[t & 3]
                    t = t >> 2
                    image[y + b, x + a, 3] = (k & 15) << 4
                    k = k >> 4

            p += 1

    return image