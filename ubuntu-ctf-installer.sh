#!/bin/bash

# Tested on Ubuntu 22.04.4

#=========================
# Initialization
#=========================
run() {
    local reset_text="\033[0m"
    local green_text="\033[0;32m"
    local red_text="\033[0;31m"
    
    local output_log="../output.log"
    local error_log="../error.log"

    mkdir -p /tmp/ubuntu-ctf-installer/workspace
    cd /tmp/ubuntu-ctf-installer/workspace

    # Extract the description ($1)
    local description="$1"

    # Extract the commands into an array ($2)
    IFS=$'\n' read -r -d '' -a commands <<< "$2"
    
    # Execute each command
    echo "##################################################"
    echo "$description"
    echo "##################################################"
    for cmd in "${commands[@]}"; do
        cmd=$(echo $cmd | awk '{$1=$1;print}')
        echo -n "[$(date +"%H:%M:%S")] $cmd"
        
        eval "$cmd" >> "$output_log" 2>> "$error_log"
        if [ $? -ne 0 ]; then
            echo -e " ... ${red_text}FAIL${reset_text}"
            return 1
        else
            echo -e " ... ${green_text}PASS${reset_text}"
        fi
    done
    echo "" # newline

    # Clean up
    rm -f /tmp/ubuntu-ctf-installer/workspace/*
    return 0
}

sudo true # force sudo password prompt
run "Install essential packages" "
  sudo apt-get update
  sudo apt-get install -y libc6:i386 vim mousepad xclip curl wget gcc jq
"

#=========================
# APT-dependent packages / tools
#=========================
run "Install flameshot" "sudo apt-get install -y flameshot"
run "Install Visual Studio Code" "
  sudo apt-get install -y wget gpg
  wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
  sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
  sudo sh -c 'echo \"deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main\" > /etc/apt/sources.list.d/vscode.list'
  rm -f packages.microsoft.gpg
  sudo apt-get update
  sudo apt-get install apt-transport-https
  sudo apt-get install -y code
"
run "Install Docker" "
  sudo apt-get install -y ca-certificates curl
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable\" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo usermod -aG docker $USER
"
run "Install LibreOffice" "sudo apt-get install -y libreoffice"
run "Install Wireshark" "
  echo \"wireshark-common wireshark-common/install-setuid boolean true\" | sudo debconf-set-selections
  sudo DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark
"
run "Install The Sleuth Kit" "sudo apt-get install -y sleuthkit"
run "Install exiftool" "sudo apt-get install -y exiftool"
run "Install binwalk" "sudo apt-get install -y binwalk"
run "Install patchelf" "sudo apt-get install -y patchelf"
run "Install Sonic Visualiser" "sudo apt-get install -y sonic-visualiser"
run "Install checksec" "sudo apt-get install -y checksec"
run "Install gobuster" "sudo apt-get install -y gobuster"

#=========================
# Python-dependent packages / tools
#=========================
run "Install Python" "sudo apt-get install -y python3 python3-pip"
run "Install Chepy" "pip install chepy[extras]"
run "Install pwntools" "pip install --no-warn-script-location pwntools"
run "Install angr" "pip install angr"
run "Install Volatility3" "
  git clone https://github.com/volatilityfoundation/volatility3.git
  cd volatility3
  pip install -r requirements.txt
  curl -o volatility3/symbols/windows.zip  https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
  curl -o volatility3/symbols/mac.zip  https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip
  curl -o volatility3/symbols/linux.zip  https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
  chmod +x vol.py
  cd ..
  sudo mv volatility3 /opt/
  sudo ln -s /opt/volatility3/vol.py /usr/bin/vol.py
"
run "Install Z3 Solver" "pip install z3-solver"
run "Install Flask-Unsign" "pip install flask-unsign"

#=========================
# Other packages / tools (compile from source / self-contained)
#=========================
run "Install Node.js" "
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
  eval \"\$(cat ~/.bashrc | tail -n +10)\" # equivalent to 'source ~/.bashrc'
  nvm install --lts
"
run "Install SecLists" "
  git clone https://github.com/danielmiessler/SecLists.git
  sudo mv SecLists /opt/
"
run "Install john jumbo" "
  sudo apt-get -y install git build-essential libssl-dev zlib1g-dev
  sudo apt-get install -y yasm pkg-config libgmp-dev libpcap-dev libbz2-dev
  git clone https://github.com/openwall/john -b bleeding-jumbo john
  cd john/src
  ./configure && make -s clean && make -sj4
  cd ../..
  sudo mv john /opt/
"
run "Install Burp Suite Community" "
  curl -o bsc.sh \"https://portswigger-cdn.net/burp/releases/download?product=community&version=2024.1.1.6&type=Linux\"
  chmod +x bsc.sh
  sudo ./bsc.sh -q
  rm -f bsc.sh
  sudo ln -s /opt/BurpSuiteCommunity/BurpSuiteCommunity /usr/bin/burp
"
run "Install IDA Free" "
  curl -O \"https://out7.hex-rays.com/files/idafree84_linux.run\"
  chmod +x idafree84_linux.run
  ./idafree84_linux.run --prefix ./idafree-8.4/ --mode unattended
  sudo mv idafree-8.4 /opt/
  sudo ln -s /opt/idafree-8.4/ida64 /usr/bin/ida
"
run "Install Ghidra" "
  sudo apt-get install -y openjdk-17-jdk
  curl -L -O \"https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20240130.zip\"
  unzip ghidra*PUBLIC*.zip
  rm -f ghidra*PUBLIC*.zip
  find . -maxdepth 1 -type d -name ghidra*PUBLIC -exec sudo mv {} /opt/ \;
  sudo curl -o /usr/bin/ghidra https://gist.githubusercontent.com/liba2k/d522b4f20632c4581af728b286028f8f/raw/0903904adb6a5f06636f179f7cf9fd94e0a4ec5d/ghidra.py
  find /opt/ -maxdepth 1 -type d -name ghidra*PUBLIC -print0 2>/dev/null | xargs -0 -I{} sudo sed -i 's,/Applications/ghidra_10.3_PUBLIC,{},g' /usr/bin/ghidra
  sudo chmod +x /usr/bin/ghidra
"
run "Install pwndbg" "
  curl -L -O \"https://github.com/pwndbg/pwndbg/releases/download/2024.02.14/pwndbg_2024.02.14_amd64.deb\"
  sudo dpkg -i pwndbg*amd64.deb
  rm -f pwndbg*amd64.deb
"
run "Install upx" "
  curl -L -O \"https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-amd64_linux.tar.xz\"
  tar -xf upx*amd64_linux.tar.xz
  rm -f upx*amd64_linux.tar.xz
  find . -maxdepth 1 -type d -name upx*amd64_linux -exec sudo mv {} /opt/ \;
  sudo ln -s /opt/upx*amd64_linux/upx /usr/bin/upx
"
run "Install Stegsolve" "
  mkdir stegsolve
  echo '#!/usr/bin/java -jar' > stegsolve/stegsolve.jar
  wget -O tmp_stegsolve.jar http://www.caesum.com/handbook/Stegsolve.jar
  cat tmp_stegsolve.jar >> stegsolve/stegsolve.jar
  rm -f tmp_stegsolve.jar
  chmod +x stegsolve/stegsolve.jar
  sudo mv stegsolve /opt/
  sudo ln -s /opt/stegsolve/stegsolve.jar /usr/bin/stegsolve
"
run "Install zsteg" "
  sudo apt-get install -y ruby-full
  sudo gem install zsteg
"
