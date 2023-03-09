#!/bin/bash
apt install python-pip &> /dev/null
pip install -r requirements.txt &> /dev/null
echo -n "token of your telegram bot : "
read token
echo -n "your chat id : "
read chatID

echo -e "token=$token\nchatID=$chatID" > LMS.cfg 