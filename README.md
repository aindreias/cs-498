This repository contains the code used for my semester project on differential neural cryptanalysis.

## Setup Instructions
The python files should be inserted into the CLAASP library.

Setup requires a UNIX environment. Given the instability of CLAASP configuration scripts (if done incorrectly, the PATH variable becomes empty and thus almost no commands are valid), it is highly recommended to do the setup on a fresh Virtual Machine / WSL instance with enough space.

The concrete steps are as follows:

1. Download Python3, using e.g. https://www.python.org/downloads/
2. Download Sage, using instructions from e.g. https://doc.sagemath.org/html/en/installation/index.html
3. Download a zipped CLAASP folder from the official repository https://github.com/Crypto-TII/claasp. For full compatibility with our code, you can download the zip release with tag 1.1 (see https://github.com/Crypto-TII/claasp/tags)
4. Follow CLAASP setup instructions: https://github.com/Crypto-TII/claasp/blob/main/docs/USER_GUIDE.md
5. Insert the provided Python code in the /claasp-main folder. To load or run a file, open a Sage terminal in /claasp-main and use the `attach` command.

## Workflow

The intended workflow is as follows:

1. Open a Sage terminal and use `attach('utils.py')`
2. Call whichever function you need (example: `evaluate_crax()`)
3. Modify the function as you see fit (e.g.: modify dataset size/ number of rounds etc.) - the `attach` command will automatically reload the code in Sage. Go back to step 2 and repeat.
