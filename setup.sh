#!/bin/bash

folder=$(find /media /home /usr /var /tmp /opt /mnt /root -type d -name recon_enum -print -quit 2>/dev/null)
echo -e '#!/bin/bash\n' > /usr/bin/reconscan
echo -e "cd  $folder && python reconscan.py \"\$@\" \n" >> /usr/bin/reconscan
chmod +x /usr/bin/reconscan
apt-get install brutespray
pip install argparse
echo '#RECON ENUM' >> ~/.bashrc
cd $folder/..
echo "RECONENUMHOME=$PWD" >> ~/.bashrc
apt-get install -y xdotool
git clone https://github.com/danielmiessler/SecLists.git $PWD/SecLists
bash