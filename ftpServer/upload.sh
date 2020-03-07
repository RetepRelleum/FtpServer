HOST=esp32.home
USER=user
PASSWORD=pw
DIRECTORY="/lib"

echo "mkdir"
echo "***************"

ftp -inv $HOST <<EOF
user $USER $PASSWORD
mkdir $DIRECTORY
bye
EOF

echo "Copy file"
echo "***************"

ftp -inv $HOST <<EOF
user $USER $PASSWORD
cd $DIRECTORY
mput ftpServer.py
bye
EOF
