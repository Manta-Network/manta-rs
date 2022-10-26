import os

register_list = []
f = open("dummy_register.csv", "r")
for line in f.readlines()[1:]:
    register_list.append(line.split(","))

# print(register_list)
# print(len(register_list))

for i in range(len(register_list)):
    command = "cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_client \"https://ceremony.manta.network\" \"" + register_list[i][4] + "\" contribute >log_trail" + str(i) + " 2>&1 &"
    os.system(command)
