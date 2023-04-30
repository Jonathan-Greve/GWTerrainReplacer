import frida
import sys

from PIL import Image

from gw_texture_manager.dds_dxt3 import process_dxt3

global_data = None


def on_message(message, data):
    if message["type"] == "send":
        print(f"[+] {message['payload']}")

        # Check if the data is present in the message payload
        if message["payload"]:
            global global_data
            global_data = message["payload"]["data"]

            # Convert the received ArrayBuffer to a bytearray

            print(f"[+] Received data length: {len(global_data)}")
        else:
            print("[-] Data not found in message payload")
    else:
        print(f"[-] {message}")

def hook_decompress_texture_fun_hook(process_name, base_offset):
    # JavaScript code to be injected
    js_code = f'''
    Interceptor.attach(ptr("{base_offset + 0x270760}"), {{
        onEnter: function (args) {{
            this.compressed_texture_data = args[0];
            this.param1 = args[1];
            this.param2 = args[2];
            this.param3 = args[3];
            this.param4 = args[4];
            this.param5 = args[5];
            this.param6 = args[6];
            this.param7 = args[7];
            
            this.decompress_texture_ptr = ptr(this.param5);

            var ebp = this.context.ebp;
            var value = ebp.add(0xA8).readPointer().readPointer().add(0x10).readPointer();
            console.log("value: " + value);
            
            this.execute_on_leave = (value == 0x1310C);
        }},
        onLeave: function (retval) {{
            if (this.execute_on_leave) {{
                console.log("onLeave");
                
                var data_size = 62667;
                var data_array = Array.from(new Uint8Array(Memory.readByteArray(
                    this.decompress_texture_ptr.readPointer(), data_size)));

                // Send the array of integers to the Python script
                send({{data: data_array}});
            }}
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

    # Make sure you have received the data before proceeding
    if global_data is not None and global_data != b"":
        # Set the dimensions of your DXT3 texture
        width, height = 256, 256

        # Process the DXT3 data
        rgba_image = process_dxt3(global_data, width, height)

        # Convert the image array to a PIL Image and save as PNG
        img = Image.fromarray(rgba_image, 'RGBA')
        img.save('output_image.png')
    else:
        print("[-] Failed to receive data")


