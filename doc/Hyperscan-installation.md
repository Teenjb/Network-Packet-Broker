# DPDK Installation
### **Reference**
- [Hyperscan start guide](https://intel.github.io/hyperscan/dev-reference/getting_started.html)

## Dependency

| Dependency | Version | Notes |
| --- | --- | --- |
| [cmake](http://www.cmake.org/) | >=2.8.11 |  |
| [ragel](http://www.colm.net/open-source/ragel/) | 6.9 |  |
| [python](http://www.python.org/) | 2.7 |  |
| [boost](http://boost.org/) | >=1.57 | Boost headers required |
| [tcpdump](http://tcpdump.org/) | >=0.8 | Optional: needed for example code only |

## Installation Step

1. Download the Hyperscan
    
    ```bash
    wget https://github.com/intel/hyperscan/archive/refs/tags/v5.4.2.tar.gz
    tar -xvf v5.4.2.tar.gz
    ```
    
2. Create Build Directory
    
    ```bash
    mkdir build
    ```
    
3. make using Ninja as generator 
    
    ```bash
    cd hyperscan-5.4.2
    sudo cmake -G Ninja <build directory>
    ```
    
4. Build using 
    
    ```bash
    cd <build directory>
    ninja
    ```
    
5. and install it using  
    
    ```bash
    sudo ninja install
    ```
    
6. Import library using this 
    
    ```c
    #include <hs/hs.h> 
    ```
    

## Performance Tips

1. Use [**`HS_FLAG_SINGLEMATCH`**](https://intel.github.io/hyperscan/dev-reference/api_constants.html#c.HS_FLAG_SINGLEMATCH) to only match one for each pattern