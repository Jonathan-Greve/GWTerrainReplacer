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


def hook_decompress_file(process_name, base_offset):
    # JavaScript code to be injected
    js_code = f'''
    Interceptor.attach(ptr("{base_offset + 0x739D0}"), {{
        onEnter: function (args) {{
            this.archive = args[0];
            this.file_id = args[1];
            this.some_flag = args[2];
            this.bytes = args[3];
            
            // Check the value of the EDX register
            var edx_value = this.context.edx.toInt32();

            // Set a flag if EDX == 0x1310C
            this.execute_on_leave = (edx_value == 0x1310C);
        }},
        onLeave: function (retval) {{
            // Check the value of the EDI register
            var edi_value = this.context.edi.toInt32();
            
            // Write 0x13 only if EDI == 0x284DB
            if (edi_value == 0x284DB) {{
                var data_ptr = new NativePointer(retval);
                var offset = 0x3855A + 0x4531;

                var target_address = data_ptr.add(offset);

                // Check if the memory address is accessible
                if (Memory.protect(target_address, 1, 'rwx')) {{
                    target_address.writeU8(0x13);
                }} else {{
                    console.error('[-] Access violation: unable to write to address', target_address);
                }}
            }}

            // Send the data back to Python when EDI == 0x1310C
            if (this.execute_on_leave) {{
                console.log("[+] EDI == 0x1310C");
                var data_ptr = new NativePointer(retval);
                var data_size = 62667; // Updated data size
                
                // Log the values for debugging
                console.log("[+] retval:", retval);
                console.log("[+] data_ptr:", data_ptr);
                console.log("[+] data_size:", data_size);
                
                // Read and log the first 10 bytes of data_ptr's data
                var first_10_bytes = Memory.readByteArray(data_ptr, 10);
                console.log("[+] First 10 bytes of data_ptr's data:", first_10_bytes);
                
                // Read the data from data_ptr and convert it to an array of integers
                var data_array = Array.from(new Uint8Array(Memory.readByteArray(data_ptr, data_size)));

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
    while global_data is None:
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
