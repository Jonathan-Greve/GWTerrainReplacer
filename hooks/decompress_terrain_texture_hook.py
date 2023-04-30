import frida
import sys

from PIL import Image

from gw_texture_manager.dds_dxt3 import process_dxt3


def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)


def hook_decompress_terrain_texture(process_name, base_offset):
    # JavaScript code to be injected
    js_code = f'''
    var LoadTexturePtr = ptr({base_offset + 0x2e5280});
    console.log("LoadTexturePtr: " + LoadTexturePtr);

    Interceptor.attach(LoadTexturePtr, {{
        onEnter: function (args) {{
            var param1 = args[0];
            
            console.log("[+] param1:", param1);
            
            var valueAtParam1Plus10 = param1.readPointer().add(0x10).readPointer();
            send("Value at *(*param1+0x10): " + valueAtParam1Plus10);
        }}
    }});
    '''

    # Attach to the target process by its name, you can use frida.spawn() if you want to start a new process
    process = frida.attach(process_name)  # Replace "target_process_name" with the actual process name

    # Create a script object
    script = process.create_script(js_code, runtime="v8")

    # Inspect in a browser. In Google Chrome: chrome://inspect/#devices
    script.enable_debugger()

    # Register the message handler
    script.on("message", on_message)

    # Load the script and start instrumenting
    script.load()

    # Keep the script running
    print("Press 'q' to quit")
    while True:
        if sys.stdin.read(1) == 'q':
            break
