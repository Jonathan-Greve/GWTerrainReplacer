import numpy as np
from PIL import Image

from gw_texture_manager.dds_dxt1 import DXT1Color


class DXT5Alpha:
    def __init__(self, a0, a1, table):
        self.a0 = a0
        self.a1 = a1
        self.table = table


def process_dxt5(data, xr, yr):
    coltable = np.empty((xr * yr // 16), dtype=DXT1Color)
    alphatable = np.empty((xr * yr // 16), dtype=DXT5Alpha)
    blocktable = np.empty((xr * yr // 16), dtype=np.uint32)

    d = np.frombuffer(data, dtype=np.uint32)

    for x in range(xr * yr // 16):
        alphatable[x] = DXT5Alpha(d[x * 4], d[x * 4 + 1], np.frombuffer(d[x * 4:x * 4 + 2], dtype=np.int64)[0])
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

            atbl = np.zeros(8, dtype=np.uint8)
            l = alphatable[p]

            atbl[0] = l.a0
            atbl[1] = l.a1

            if l.a0 > l.a1:
                for z in range(6):
                    atbl[z + 2] = ((6 - z) * l.a0 + (z + 1) * l.a1) // 7
            else:
                for z in range(4):
                    atbl[z + 2] = ((4 - z) * l.a0 + (z + 1) * l.a1) // 5
                atbl[6] = 0
                atbl[7] = 255

            t = blocktable[p]
            k = l.table

            for b in range(4):
                for a in range(4):
                    image[y + b, x + a] = ctbl[t & 3]
                    t = t >> 2
                    image[y + b, x + a, 3] = atbl[k & 7]
                    k = k >> 3

            p += 1

    return image