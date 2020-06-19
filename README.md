![](./resources/official_armmbed_example_badge.png)
# Running PSA Attestation examples on Mbed OS
This repository contains an example demonstrating the compilation and use of PSA Attestation on Mbed OS.

Example contained within this repository is inject attestation key-pair, get attetstaion token size and attetstaion token.

## Prerequisites
* Install <a href='https://github.com/ARMmbed/mbed-cli#installing-mbed-cli'>Mbed CLI</a>

## Import
The following are the steps required to install the application:
* Clone the repository and deploy the Mbed OS project: `mbed import git@github.com:ARMmbed/mbed-os-example-attestation.git`
* Change your current directory: `cd mbed-os-example-mbed-attestation`

## Compile
To compile the example program use `mbed compile` while specifying the target platform and the compiler.
For example, in order to compile using the ARM GCC compiler and a K64F target platform use: `mbed compile -m K64F -t GCC_ARM`.

Once the compilation is completed successfully a binary file will be created: `./BUILD/K64F/GCC_ARM/mbed-os-example-mbed-attestation.bin`

## Program your board
1. Connect your Mbed device to the computer over USB.
1. Copy the binary file (`mbed-os-example-mbed-attestation.bin`) to the Mbed device.

## Run
1. Connect to the Mbed Device using a serial client application of your choice.
1. Press the reset button on the Mbed device to run the program.

The expected output from a successful execution of the example program should be as follows:
```
Get attestation tGet attestation token:
        success!
```

## Troubleshooting
If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.

### License and contributions

The software is provided under Apache-2.0 license. Contributions to this project are accepted under the same license. Please see contributing.md for more info.

This project contains code from other projects. The original license text is included in those source files. They must comply with our license guide.
