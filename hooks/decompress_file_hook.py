import frida
import sys

def on_message(message, data):
    if message["type"] == "send":
        print(f"[+] {message['payload']}")
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
        }}
    }});
    '''

    # Attach to the target process by its name, you can use frida.spawn() if you want to start a new process
    process = frida.attach(process_name)  # Replace "target_process_name" with the actual process name

    # Create a script object
    script = process.create_script(js_code, runtime="v8")

    # Register the message handler
    script.on("message", on_message)

    # Load the script and start instrumenting
    script.load()

    # Keep the script running
    print("Press 'q' to quit")
    while True:
        if sys.stdin.read(1) == 'q':
            break

