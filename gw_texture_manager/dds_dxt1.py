import numpy as np
from PIL import Image


class DXT1Color:
    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2
        self.r1, self.g1, self.b1 = self._decode_color(c1)
        self.r2, self.g2, self.b2 = self._decode_color(c2)

    @staticmethod
    def _decode_color(c):
        r = (c >> 11) & 0x1F
        g = (c >> 5) & 0x3F
        b = c & 0x1F
        return r << 3, g << 2, b << 3


def process_dxt1(data, xr, yr):
    coltable = np.empty((xr * yr // 16), dtype=DXT1Color)
    blocktable = np.empty((xr * yr // 16), dtype=np.uint32)

    d = np.frombuffer(data, dtype=np.uint32)

    for x in range(xr * yr // 16):
        coltable[x] = DXT1Color(d[x * 2], d[x * 2 + 1])
        blocktable[x] = d[x * 2 + 1]

    image = np.zeros((yr, xr, 4), dtype=np.uint8)

    p = 0
    for y in range(0, yr, 4):
        for x in range(0, xr, 4):
            ctbl = np.zeros((4, 4), dtype=np.uint8)
            ctbl[:, 3] = 255
            c = coltable[p]
            ctbl[0, :3] = c.r1, c.g1, c.b1
            ctbl[1, :3] = c.r2, c.g2, c.b2

            if c.c1 > c.c2:
                ctbl[2, :3] = (ctbl[0, :3] * 2 + ctbl[1, :3]) // 3
                ctbl[3, :3] = (ctbl[0, :3] + ctbl[1, :3] * 2) // 3
            else:
                ctbl[2, :3] = (ctbl[0, :3] + ctbl[1, :3]) // 2
                ctbl[3, :3] = 0
                ctbl[3, 3] = 0

            t = blocktable[p]

            for b in range(4):
                for a in range(4):
                    image[y + b, x + a] = ctbl[t & 3]
                    t = t >> 2

            p += 1

    return image