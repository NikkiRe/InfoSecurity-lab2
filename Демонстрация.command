#!/bin/zsh
cd -- "${0:A:h}"
python3 demo.py --pause
printf '\nНажмите Enter, чтобы закрыть демонстрацию.\n'
read -r
