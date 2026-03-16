# System Setup

To operate our sandbox environment, you will need 2 VMs running at the same time: 
- Ubuntu for Defense 
- Kali Linux for Attack. 
  
It is highly recommended to SSH in from 2 separate terminal instances on your local machine to make installation and operation easier.

# Defense - Go Application
## SSH setup
### 1. Install the SSH Server

Ubuntu does not always come with the SSH daemon active. Run this in the VirtualBox window first:

    sudo apt update 

    sudo apt install openssh-server -y

### 2. Enable and Start the Service
This ensures the VM is open for connections. Watch out for the systemctl spelling.

    sudo systemctl enable ssh 

    sudo systemctl start ssh 

### 3. Verify it's working: 
Run:

    sudo systemctl status ssh
   
   You want to see active (running) in green text.

### 4. Find the Correct IP Address
This is the Address of the VM on your private host-only network.

In the Ubuntu terminal, run: 

    ip a 

Look for the interface named enp0s8 (it might be enp0s3 or eth1 depending on your setup).

Find the inet address starting with ` 192.168.56.x.`

Note: Do NOT use the `10.0.2.15` address; that is the NAT address and won't work from your laptop.

### 5. Connect from the Host (Laptop)
Now, open a terminal on the Host Machine (not inside VirtualBox) and run:

Run:

    ssh <ubuntu_username>@192.168.56.x 
Replace <ubuntu_username> with your actual Ubuntu login name and the x with your specific IP.

## Troubleshooting
If you are still unable to connect via SSH, you may need use Port Forwarding.

### Port Forwarding Alternative

In Virtual Box, go to Network > Adapter 1 (NAT) > Advanced > Port Forwarding.

Add a new rule:

    Name: SSH

    Protocol: TCP

    Host IP: 127.0.0.1

    Host Port: 2222

    Guest Port: 22

To Connect:
        
    ssh <user>@127.0.0.1 -p 2222.
## Go Install

### 1. Update the System
Always start here to make sure you aren't grabbing outdated packages.

    sudo apt update && sudo apt upgrade -y

### 2. Install Go and LibPcap
We need libpcap-dev because our Go code uses C-bindings to talk to the network card. Without it, you will get a "pcap.h not found" error.

    sudo apt install golang libpcap-dev -y
### 3. Verify the Installation
Check that Go is alive and well:

    go version

It should return something like go ` version go1.x.x linux/amd64.`

### 4. Setting up the Project Folder
Now, you need to get the code and sync the dependencies.

#### Clone the Repository:

    git clone <your-github-url-here>
    cd "IntrusionDetectionSystem/Team\ 1/BLUE"

#### Sync the Go Modules:

 we are using github.com/google/gopacket, we need to download that library into the local environment.

    go mod tidy

This command looks at the main.go file, sees what's missing, and downloads it automatically.



#### Run the app:

Before trying to catch attacks, make sure the code actually compiles on your machine.


    sudo go run main.go

If you want to make sure your environment is 100% correct, try building a standalone binary:

    go build -o goguard
If this finishes without errors, you'll have a file named goguard that they can run with ` sudo ./goguard `. It’s much faster than using go run every time.


# Kali Attack
Kali requires the SSH service to be manually started and the Scapy library installed for packet forging.

## 1. Enable SSH
Run this in the Kali VM window:

    sudo apt update
    sudo apt install openssh-server -y
    sudo systemctl enable ssh --now
## 2. Clone the Repo
Download the project:

    git clone <your-github-url-here>
    cd "IntrusionDetectionSystem/Team\ 1/RED"
## 2. Connect from your Laptop
Find your IP (usually on eth1) with ip a, then connect on your local terminal:

    ssh kali@192.168.56.x


# Running the Connection Test
Once both environments are configured and you are SSH'd into both machines, follow these steps to verify that the listener can detect traffic from the attacker.

## 1. Start the Defender (Ubuntu)
Navigate to your BLUE folder and start the Go application. It must stay running to capture the incoming packets.

    cd "IntrusionDetectionSystem/Team\ 1/BLUE"
    sudo go run main.go

Verify that you see the message: ` GoGuard: Monitoring enp0s8. Waiting for packets...` 

## 2. Verify the Ubuntu IP
If you have forgotten the IP of your Ubuntu machine, run this command in a separate Ubuntu terminal tab or look at your previous ip a output:

    ip a
Locate the address for `enp0s8` (e.g., 192.168.56.105).

## 3. Launch the Attack (Kali)
In your Kali terminal, navigate to the RED folder and execute the Python script. You must pass the Ubuntu IP you found in the previous step as a command-line argument.

    cd "IntrusionDetectionSystem/Team\ 1/RED"
    python3 orchestrator.py <TARGET_UBUNTU_IP>
Example:   `python3 orchestrator.py 192.168.56.105`

## 4.Confirm Detection
Switch back to your Ubuntu terminal. You should see several lines of output appearing in real-time as the pings arrive:

    [14:15:01] Detection: 192.168.56.101 --> 192.168.56.105 | Proto: ICMPv4
    [14:15:01] Detection: 192.168.56.105 --> 192.168.56.101 | Proto: ICMPv4

### Expected Results
#### On Kali: 
The script should report that 4 packets were transmitted and received with 0% packet loss.

#### On Ubuntu: 
You should see exactly 8 lines of detection for a 4-packet ping (4 requests from Kali and 4 replies from Ubuntu).

#### Noise Filtering: 
If you are still seeing UDP traffic from 192.168.56.100 or .255, ensure you have pulled the latest version of main.go with the updated BPF filters.
