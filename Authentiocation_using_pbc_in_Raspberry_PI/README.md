# PBC Library Installation and Environment Configuration Guide

This guide provides detailed instructions for installing and configuring the **Pairing-Based Cryptography (PBC)** library on Linux, and for cross-compiling it to run on ARM-based devices such as the **Raspberry Pi**. It also includes setup instructions for communication between two devices: a host PC and a Raspberry Pi.

---

## 1. Install Dependencies (on Linux PC)

```bash
sudo apt-get update
sudo apt-get install build-essential libgmp-dev m4
```

---

## 2. Install PBC on Linux (x86)

```bash
wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14

# Configure, compile, and install
./configure
make
sudo make install
```

Verify that the GMP library is installed:

```bash
sudo apt-get install libgmp-dev
```

Test your setup by compiling and running an example program:

```bash
gcc -o foo test.c -I /usr/local/include/pbc -L /usr/local/lib -lpbc -lgmp
./foo ./param/a.param
```

---

## 3. Configure ARM GCC Environment

The default GCC compiler is for x86 architecture and cannot produce binaries for ARM-based devices. Therefore, we need to configure an ARM GCC cross-compilation environment.

### Download ARM GCC Toolchain

```bash
wget https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-a/9.2-2019.12/binrel/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf.tar.xz
sudo tar -xvf gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf.tar.xz -C /usr/local/arm/
```

### Add to Environment Variables

```bash
sudo vi /etc/profile
```

Add the following line at the end:

```bash
export PATH=$PATH:/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf/bin
```

Then refresh and reboot:

```bash
source /etc/profile
reboot
```

### Verify Installation

```bash
arm-none-linux-gnueabihf-gcc -v
```

---

## 4. Install GMP for ARM

```bash
sudo apt-get update
sudo apt-get install lsb-core lib32stdc++6

wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz
tar -xf gmp-6.2.1.tar.xz
cd gmp-6.2.1

./configure --host=arm-none-linux-gnueabihf --enable-cxx --prefix=/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf
make
make install
```

---

## 5. Install PBC for ARM

```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14

./configure --host=arm-none-linux-gnueabihf --prefix=/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf/pbc CC=arm-none-linux-gnueabihf-gcc LDFLAGS="-L/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf/lib" CPPFLAGS="-I/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf/include"

make
make install
```

---

## 6. Compile C Code for ARM

```bash
arm-none-linux-gnueabihf-gcc -o standard standard.c -I/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf/include -L/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf/lib -lgmp -I/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf/pbc/include -L/usr/local/arm/gcc-arm-9.2-2019.12-x86_64-arm-none-linux-gnueabihf/pbc/lib -lpbc
```

Transfer the compiled executable to the Raspberry Pi.

---

## 7. Run the Program on Raspberry Pi

First, link the PBC libraries on the Raspberry Pi:

```bash
export LD_LIBRARY_PATH=/home/root/pbc/lib:$LD_LIBRARY_PATH
```

Run your program:

```bash
./test param/a.param
```

---

## 8. Connecting the Two Devices (PC and Raspberry Pi)

Your setup involves **two devices**:

- **Device 1:** Local computer (used for compilation and control)
- **Device 2:** Raspberry Pi (runs the ARM executable)

The devices are **physically connected** (e.g., via Ethernet or USB cable). You can communicate between them using their **IP addresses**.

Example connection command from the PC to the Raspberry Pi:

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa,ssh-dss root@192.168.7.1
```

Ensure that:

- The **Raspberry Pi** has a functioning **network interface** and **signal receiver**.
- **Firewall settings** allow communication between the devices.
- The **library versions** on both devices are compatible with their respective architectures.
- The **PBC** and **GMP** libraries have been **correctly compiled** and **linked**.

If issues occur, check for version mismatches or incomplete builds.

---

## 9. Troubleshooting

- Verify all dependencies are installed.
- Confirm the ARM compiler path is set correctly.
- Rebuild GMP and PBC if library linking fails.
- Check the Raspberry Pi’s SSH accessibility and network configuration.

##  10. References
- [PBC Official Website](http://crypto.stanford.edu/pbc)
- [GMP Official Website](https://gmplib.org)
- [ARM GNU Toolchain](https://developer.arm.com)
