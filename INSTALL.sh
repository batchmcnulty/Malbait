echo "Changing permissions...."
echo "Copying malbait.pl into /usr/bin..."
sudo cp malbait.pl /usr/bin/malbait
sudo cp mail_report.py /usr/bin/mail_report.py
sudo chmod +777 /usr/bin/malbait
sudo chmod +777 /usr/bin/mail_report.py
echo " Done. Bye now!"
