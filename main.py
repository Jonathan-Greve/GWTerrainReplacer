import os
import sys

from hooks.decompress_terrain_texture_hook import hook_decompress_terrain_texture
from process_helpers.get_process_base_address import get_process_base_address
from hooks.decompress_file_hook import hook_decompress_file

# Example usage
if __name__ == "__main__":
    process_name = "Gw.exe"
    module_name = "Gw.exe"

    base_address = get_process_base_address(process_name, module_name)
    print(f"Base address: {hex(base_address)}")

    hook_decompress_terrain_texture(process_name, base_address)
    hook_decompress_file(process_name, base_address)