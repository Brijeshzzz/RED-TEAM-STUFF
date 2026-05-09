from pwn import *

context.binary = './razz_challenge'
context.log_level = 'error'

# Start under gdb
p = gdb.debug('./razz_challenge', '''
set pagination off

# bypass ptrace
catch syscall ptrace
commands
    set $rax=0
    continue
end

continue
''')

sleep(2)

# Pause execution
p.send_signal(signal.SIGINT)
sleep(1)

# Attach gdb with better tracing
gdb.attach(p, '''
set pagination off

# Print every instruction near execution
display/i $pc

# Show registers continuously
display $rax
display $rbx
display $rcx

continue
''')

print("[*] Look at registers — decoded bytes will appear in rax/al")
print("[*] Wait ~5 seconds...")

sleep(5)

p.close()
