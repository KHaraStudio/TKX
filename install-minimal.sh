#!/bin/bash
echo "Minimal TKX Installer"
pip install requests 2>/dev/null || python3 -m pip install requests
chmod +x tkx_cli.py tkx_autopwn.py
echo "alias tkx='python $(pwd)/tkx_cli.py'" >> ~/.bashrc
echo "alias tkx-autopwn='python $(pwd)/tkx_autopwn.py'" >> ~/.bashrc
source ~/.bashrc 2>/dev/null
echo "Done! Use: tkx -u http://target.com"
